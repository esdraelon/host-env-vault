use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use zeroize::{Zeroize, Zeroizing};

use crate::core::error::Error;
use crate::core::slot::NAME_MAX_BYTES;

/// Runtime frames name an entry on the profile's runtime list. The socket path
/// selects the profile; the body is the entry name (UTF-8), not a secret value.
pub const OP_FETCH_ENV: u8 = 1;
pub const OP_FETCH_FILE: u8 = 2;
pub const ST_OK: u8 = 0;
pub const ST_DENIED: u8 = 1;

const MAX_BODY: usize = NAME_MAX_BYTES;

pub struct Response {
    pub status: u8,
    pub body: Zeroizing<Vec<u8>>,
}

pub fn dispatch_denied() -> Response {
    Response {
        status: ST_DENIED,
        body: Zeroizing::new(Vec::new()),
    }
}

pub fn bind_runtime_socket(runtime_dir: &Path, profile_name: &str) -> Result<UnixListener, Error> {
    let sockets = runtime_dir.join("sockets");
    std::fs::create_dir_all(&sockets)?;
    let path = sockets.join(format!("{profile_name}.sock"));
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn handle_connection_frames<F>(stream: &mut UnixStream, mut on_frame: F) -> Result<(), Error>
where
    F: FnMut(u8, &[u8]) -> Result<Response, Error>,
{
    loop {
        let mut frame = match read_frame(stream) {
            Ok(frame) => frame,
            Err(Error::Io(err)) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        let response = on_frame(frame.opcode, &frame.body)?;
        frame.body.zeroize();
        write_response(stream, &response)?;
    }
}

pub fn wait_for_socket(
    listener: &UnixListener,
    timeout: std::time::Duration,
) -> Result<bool, Error> {
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

pub fn write_response(stream: &mut UnixStream, response: &Response) -> Result<(), Error> {
    let len = u32::try_from(response.body.len()).expect("response fits");
    stream.write_all(&[response.status])?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(&response.body)?;
    Ok(())
}

pub fn peer_uid(stream: &UnixStream) -> Result<u32, Error> {
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
    if resp_len > crate::core::slot::SECRET_MAX_BYTES {
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
    use std::os::unix::net::UnixStream;
    use std::thread;

    #[test]
    fn bind_uses_profile_name_in_socket_path() {
        let dir = PathBuf::from(format!("/tmp/hev-sock-name-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let listener = bind_runtime_socket(&dir, "app-worker").unwrap();
        let path = listener
            .local_addr()
            .unwrap()
            .as_pathname()
            .expect("bound unix socket path")
            .to_path_buf();
        assert_eq!(path, dir.join("sockets").join("app-worker.sock"));
        drop(listener);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn frame_round_trip_through_connection_handler() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            handle_connection_frames(&mut server, |opcode, body| {
                let _ = opcode;
                Ok(Response {
                    status: ST_OK,
                    body: Zeroizing::new(body.to_vec()),
                })
            })
            .unwrap();
        });
        let response = exchange(&mut client, OP_FETCH_ENV, b"APP_KEY").unwrap();
        assert_eq!(response.status, ST_OK);
        assert_eq!(&response.body[..], b"APP_KEY");
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn read_frame_rejects_oversize_body() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(&[OP_FETCH_ENV]).unwrap();
        client
            .write_all(&(MAX_BODY as u32 + 1).to_le_bytes())
            .unwrap();
        drop(client);
        assert!(matches!(read_frame(&mut server), Err(Error::RuntimeBody)));
    }

    #[test]
    fn handler_propagates_frame_callback_errors() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        let client = thread::spawn(move || {
            client.write_all(&[OP_FETCH_ENV, 1, 0, 0, 0, b'X']).unwrap();
        });
        let err =
            handle_connection_frames(&mut server, |_, _| Err(Error::RuntimeBody)).unwrap_err();
        assert!(matches!(err, Error::RuntimeBody));
        client.join().unwrap();
    }

    #[test]
    fn wait_for_socket_returns_true_when_peer_connects() {
        let dir = PathBuf::from(format!("/tmp/hev-poll-in-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let listener = bind_runtime_socket(&dir, "app-worker").unwrap();
        let path = dir.join("sockets").join("app-worker.sock");
        let waiter = thread::spawn(move || {
            wait_for_socket(&listener, std::time::Duration::from_secs(2)).unwrap()
        });
        thread::sleep(std::time::Duration::from_millis(50));
        let _ = UnixStream::connect(&path).unwrap();
        assert!(waiter.join().unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn handle_connection_frames_exits_cleanly_on_peer_close() {
        let (mut server, client) = UnixStream::pair().unwrap();
        drop(client);
        handle_connection_frames(&mut server, |_, _| {
            Ok(Response {
                status: ST_OK,
                body: Zeroizing::new(Vec::new()),
            })
        })
        .unwrap();
    }

    #[test]
    fn read_frame_accepts_max_length_body() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        let body = vec![b'z'; MAX_BODY];
        client.write_all(&[OP_FETCH_ENV]).unwrap();
        client.write_all(&(MAX_BODY as u32).to_le_bytes()).unwrap();
        client.write_all(&body).unwrap();
        let frame = read_frame(&mut server).unwrap();
        assert_eq!(frame.body.len(), MAX_BODY);
    }

    #[test]
    fn wait_for_socket_times_out_without_connection() {
        let dir = PathBuf::from(format!("/tmp/hev-poll-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let listener = bind_runtime_socket(&dir, "app-worker").unwrap();
        assert!(!wait_for_socket(&listener, std::time::Duration::from_millis(10)).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
