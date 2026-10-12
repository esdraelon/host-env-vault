use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use zeroize::{Zeroize, Zeroizing};

use crate::bundle;
use crate::error::Error;
use crate::kek::AgeKek;
use crate::profile::ProfileId;

/// Runtime frames carry a 32-byte key, never a profile name and never an env
/// secret. The socket path selects the profile. A longer body is rejected so
/// this cannot become a general encryption oracle.
pub const OP_WRAP: u8 = 1;
pub const OP_UNWRAP: u8 = 2;
pub const ST_OK: u8 = 0;
pub const ST_DENIED: u8 = 1;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const WRAPPED_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;
const MAX_BODY: usize = WRAPPED_LEN;
const RUNTIME_AAD_PREFIX: &[u8] = b"hev-runtime-v1\0";

pub struct Response {
    pub status: u8,
    pub body: Zeroizing<Vec<u8>>,
}

/// Data keys for profiles that expose runtime wrap. Secret entries from the
/// bundle are dropped before this returns.
pub struct RuntimeKeys {
    pub profile: ProfileId,
    pub dek: Zeroizing<[u8; 32]>,
}

pub fn load_runtime_keys(state_dir: &Path, kek: &AgeKek) -> Result<Vec<RuntimeKeys>, Error> {
    let mut loaded = Vec::new();
    for profile in crate::profile::ALL {
        if !profile.policy().runtime_key_wrap {
            continue;
        }
        let path = state_dir.join(format!("{}.hev", profile.as_str()));
        let bytes = std::fs::read(&path)?;
        let opened = bundle::open(&bytes, kek)?;
        if opened.profile != profile {
            return Err(Error::ProfileMismatch {
                found: opened.profile.as_str().to_owned(),
                expected: profile.as_str().to_owned(),
            });
        }
        loaded.push(RuntimeKeys {
            profile,
            dek: opened.dek,
        });
    }
    if loaded.is_empty() {
        return Err(Error::NoRuntimeBundles(state_dir.to_path_buf()));
    }
    Ok(loaded)
}

pub fn dispatch(profile: ProfileId, dek: &[u8; 32], opcode: u8, body: &[u8]) -> Response {
    let result = match opcode {
        OP_WRAP if body.len() == KEY_LEN => wrap_key(profile, dek, body),
        OP_UNWRAP if body.len() == WRAPPED_LEN => unwrap_key(profile, dek, body),
        _ => Err(Error::RuntimeBody),
    };
    match result {
        Ok(body) => Response {
            status: ST_OK,
            body: Zeroizing::new(body),
        },
        Err(_) => Response {
            status: ST_DENIED,
            body: Zeroizing::new(Vec::new()),
        },
    }
}

pub fn handle_connection(
    stream: &mut UnixStream,
    profile: ProfileId,
    dek: &[u8; 32],
    require_uid: Option<u32>,
) -> Result<(), Error> {
    let uid = peer_uid(stream)?;
    if let Some(expected) = require_uid {
        if uid != expected {
            write_response(stream, &dispatch_denied())?;
            return Err(Error::PeerUid { actual: uid });
        }
    }
    loop {
        let mut frame = match read_frame(stream) {
            Ok(frame) => frame,
            Err(Error::Io(err)) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        let response = dispatch(profile, dek, frame.opcode, &frame.body);
        frame.body.zeroize();
        write_response(stream, &response)?;
    }
}

pub fn serve_forever(
    listener: UnixListener,
    state_dir: &Path,
    kek: &AgeKek,
    require_uid: Option<u32>,
    poll_every: std::time::Duration,
) -> Result<(), Error> {
    let profile = ProfileId::DenariusWorker;
    let mut keys = load_runtime_keys(state_dir, kek)?;
    loop {
        if wait_for_socket(&listener, poll_every)? {
            let (mut stream, _) = listener.accept()?;
            let Some(keys) = keys.iter().find(|item| item.profile == profile) else {
                return Err(Error::NoRuntimeBundles(state_dir.to_path_buf()));
            };
            if let Err(err) = handle_connection(&mut stream, profile, &keys.dek, require_uid) {
                eprintln!("host-env-vault: {err}");
            }
        } else if let Err(err) = reload(&mut keys, state_dir, kek) {
            eprintln!("host-env-vault: reload failed: {err}");
        }
    }
}

fn reload(keys: &mut Vec<RuntimeKeys>, state_dir: &Path, kek: &AgeKek) -> Result<(), Error> {
    *keys = load_runtime_keys(state_dir, kek)?;
    Ok(())
}

fn wait_for_socket(listener: &UnixListener, timeout: std::time::Duration) -> Result<bool, Error> {
    let mut fd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let rc = unsafe { libc::poll(&mut fd, 1, millis) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(Error::Io(err));
    }
    Ok(rc > 0 && (fd.revents & libc::POLLIN) != 0)
}

pub fn bind_runtime_socket(runtime_dir: &Path, profile: ProfileId) -> Result<UnixListener, Error> {
    if !profile.policy().runtime_key_wrap {
        return Err(Error::EntryNotAllowed {
            name: profile.as_str().to_owned(),
            kind: "socket",
            profile: profile.as_str().to_owned(),
        });
    }
    let sockets = runtime_dir.join("sockets");
    std::fs::create_dir_all(&sockets)?;
    let path = sockets.join(format!("{}.sock", profile.as_str()));
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

struct Frame {
    opcode: u8,
    body: Vec<u8>,
}

fn read_frame(stream: &mut UnixStream) -> Result<Frame, Error> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_BODY {
        return Err(Error::RuntimeBody);
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(Frame {
        opcode: header[0],
        body,
    })
}

fn write_response(stream: &mut UnixStream, response: &Response) -> Result<(), Error> {
    let len = u32::try_from(response.body.len()).expect("response fits");
    stream.write_all(&[response.status])?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(&response.body)?;
    Ok(())
}

fn dispatch_denied() -> Response {
    Response {
        status: ST_DENIED,
        body: Zeroizing::new(Vec::new()),
    }
}

fn runtime_aad(profile: ProfileId) -> Vec<u8> {
    let mut aad = Vec::from(RUNTIME_AAD_PREFIX);
    aad.extend_from_slice(profile.as_str().as_bytes());
    aad
}

fn wrap_key(profile: ProfileId, dek: &[u8; 32], key: &[u8]) -> Result<Vec<u8>, Error> {
    bundle::seal_key(dek, &runtime_aad(profile), key)
}

fn unwrap_key(profile: ProfileId, dek: &[u8; 32], wrapped: &[u8]) -> Result<Vec<u8>, Error> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(Error::RuntimeBody);
    }
    bundle::open_key(dek, &runtime_aad(profile), wrapped)
}

fn peer_uid(stream: &UnixStream) -> Result<u32, Error> {
    let fd = stream.as_raw_fd();
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        let mut uid = 0u32;
        let mut gid = 0u32;
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        Ok(uid)
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        Ok(cred.uid)
    }
}

/// Client side of one frame. Tests and a future worker use this shape.
pub fn exchange(stream: &mut UnixStream, opcode: u8, body: &[u8]) -> Result<Response, Error> {
    let len = u32::try_from(body.len()).expect("request fits");
    stream.write_all(&[opcode])?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(body)?;
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let resp_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if resp_len > MAX_BODY {
        return Err(Error::RuntimeBody);
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;
    Ok(Response {
        status: header[0],
        body: Zeroizing::new(resp),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{self, random_array, Entry};
    use crate::profile::Kind;
    use std::os::unix::net::UnixStream;
    use std::thread;

    #[test]
    fn wrap_round_trip_is_bound_to_the_socket_profile() {
        let dek = random_array::<32>().unwrap();
        let other = random_array::<32>().unwrap();
        let key = random_array::<32>().unwrap();
        let wrapped = dispatch(ProfileId::DenariusWorker, &dek, OP_WRAP, &key);
        assert_eq!(wrapped.status, ST_OK);
        assert_eq!(wrapped.body.len(), WRAPPED_LEN);

        let unwrapped = dispatch(ProfileId::DenariusWorker, &dek, OP_UNWRAP, &wrapped.body);
        assert_eq!(unwrapped.status, ST_OK);
        assert_eq!(&unwrapped.body[..], &key);

        let wrong_dek = dispatch(ProfileId::DenariusWorker, &other, OP_UNWRAP, &wrapped.body);
        assert_eq!(wrong_dek.status, ST_DENIED);

        let named = dispatch(ProfileId::DenariusWorker, &dek, OP_UNWRAP, b"denarius-web");
        assert_eq!(named.status, ST_DENIED);
    }

    #[test]
    fn load_runtime_keys_ignores_a_corrupt_non_runtime_bundle() {
        let kek = AgeKek::generate();
        let dir = std::env::temp_dir().join(format!("hev-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let worker = bundle::seal(
            ProfileId::DenariusWorker,
            vec![Entry {
                name: "APP_KEY".to_owned(),
                kind: Kind::Env,
                bytes: Zeroizing::new(b"app-key-value".to_vec()),
            }],
            &kek,
        )
        .unwrap();
        std::fs::write(dir.join("denarius-worker.hev"), &worker).unwrap();
        std::fs::write(dir.join("denarius-web.hev"), b"not-a-bundle").unwrap();

        let keys = load_runtime_keys(&dir, &kek).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].profile, ProfileId::DenariusWorker);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn socket_checks_peer_uid_and_wraps_a_key() {
        let dir = std::env::temp_dir().join(format!(
            "hev-sock-{}-{}",
            std::process::id(),
            random_array::<4>().unwrap()[0]
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let listener = bind_runtime_socket(&dir, ProfileId::DenariusWorker).unwrap();
        let path = dir.join("sockets").join("denarius-worker.sock");
        let dek = random_array::<32>().unwrap();
        let uid = unsafe { libc::getuid() };

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_connection(&mut stream, ProfileId::DenariusWorker, &dek, Some(uid)).unwrap();
        });

        let mut client = UnixStream::connect(&path).unwrap();
        let key = random_array::<32>().unwrap();
        let wrapped = exchange(&mut client, OP_WRAP, &key).unwrap();
        assert_eq!(wrapped.status, ST_OK);
        let unwrapped = exchange(&mut client, OP_UNWRAP, &wrapped.body).unwrap();
        assert_eq!(unwrapped.status, ST_OK);
        assert_eq!(&unwrapped.body[..], &key);
        drop(client);
        server.join().unwrap();

        let listener = bind_runtime_socket(&dir, ProfileId::DenariusWorker).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let err = handle_connection(
                &mut stream,
                ProfileId::DenariusWorker,
                &random_array::<32>().unwrap(),
                Some(u32::MAX),
            )
            .unwrap_err();
            assert!(matches!(err, Error::PeerUid { .. }));
        });
        let mut client = UnixStream::connect(&path).unwrap();
        let denied = exchange(&mut client, OP_WRAP, &key).unwrap();
        assert_eq!(denied.status, ST_DENIED);
        drop(client);
        server.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn web_profile_has_no_socket() {
        let dir = std::env::temp_dir().join(format!("hev-nosock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        assert!(bind_runtime_socket(&dir, ProfileId::DenariusWeb).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn dispatch_rejects_bad_opcode_and_body_length() {
        let dek = random_array::<32>().unwrap();
        let denied = dispatch(ProfileId::DenariusWorker, &dek, 99, &[]);
        assert_eq!(denied.status, ST_DENIED);
        let short = dispatch(ProfileId::DenariusWorker, &dek, OP_WRAP, &[0u8; 8]);
        assert_eq!(short.status, ST_DENIED);
    }

    #[test]
    fn load_runtime_keys_errors_when_runtime_bundle_is_missing() {
        let dir = std::env::temp_dir().join(format!("hev-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let kek = AgeKek::generate();
        assert!(matches!(
            load_runtime_keys(&dir, &kek),
            Err(Error::Io(_))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn load_runtime_keys_detects_profile_mismatch_in_bundle() {
        let kek = AgeKek::generate();
        let dir = std::env::temp_dir().join(format!("hev-mismatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let web = bundle::seal(
            ProfileId::DenariusWeb,
            vec![Entry {
                name: "DB_PASS".to_owned(),
                kind: Kind::Env,
                bytes: Zeroizing::new(b"x".to_vec()),
            }],
            &kek,
        )
        .unwrap();
        std::fs::write(dir.join("denarius-worker.hev"), &web).unwrap();
        assert!(matches!(
            load_runtime_keys(&dir, &kek),
            Err(Error::ProfileMismatch { .. })
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wait_for_socket_times_out_without_connection() {
        let dir = std::env::temp_dir().join(format!("hev-poll-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let listener = bind_runtime_socket(&dir, ProfileId::DenariusWorker).unwrap();
        assert!(!wait_for_socket(&listener, std::time::Duration::from_millis(10)).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
