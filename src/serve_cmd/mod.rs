//! **Serve command** — catalog-driven unix socket per profile with `socket=true`.
//! Each request names a runtime-listed entry; the profile is unpacked from the
//! local bundle into a slot under the fixed 2000 ms lease. No SSM at serve time.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::catalog::{load_catalog_snapshot, validate_serve_entry, Catalog, ProfileDefinition};
use crate::error::Error;
use crate::kek::AgeKek;
use crate::local_bundle::open_profile_into_slot;
use crate::profile::Kind;
use crate::serve::{
    bind_runtime_socket, dispatch_denied, handle_connection_frames, peer_uid, write_response,
    Response, ST_OK, OP_FETCH_ENV, OP_FETCH_FILE,
};
use crate::slot::{Slot, SlotError, SlotLease, SlotTable, LEASE_MS, NAME_MAX_BYTES};
use crate::sync::{bundle_path, DEFAULT_STATE_DIR};

pub const SERVE_SLOT_INDEX: usize = 2;
const SERVE_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);
pub const SWEEP_INTERVAL: Duration = Duration::from_millis(LEASE_MS);

/// CLI paths for one serve run (single profile socket).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeOptions {
    pub identity_path: PathBuf,
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub profile_name: String,
}

impl ServeOptions {
    pub fn new(
        identity_path: PathBuf,
        state_dir: PathBuf,
        runtime_dir: PathBuf,
        profile_name: impl Into<String>,
    ) -> Self {
        Self {
            identity_path,
            state_dir,
            runtime_dir,
            profile_name: profile_name.into(),
        }
    }

    pub fn with_default_state_dir(
        identity_path: PathBuf,
        runtime_dir: PathBuf,
        profile_name: impl Into<String>,
    ) -> Self {
        Self {
            identity_path,
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            runtime_dir,
            profile_name: profile_name.into(),
        }
    }
}

/// Load the catalog snapshot and bind the profile socket when allowed.
pub fn bind_serve_socket(options: &ServeOptions) -> Result<(std::os::unix::net::UnixListener, Catalog), Error> {
    let catalog = load_catalog_snapshot(&options.state_dir)?;
    ensure_socket_profile(&catalog, &options.profile_name)?;
    let listener = bind_runtime_socket(&options.runtime_dir, &options.profile_name)?;
    Ok((listener, catalog))
}

/// Serve one profile socket until the process exits. Sweeps expired slots every
/// [`SWEEP_INTERVAL`] and reloads the catalog snapshot on idle polls.
pub fn serve_profile_forever(
    listener: std::os::unix::net::UnixListener,
    kek: &AgeKek,
    table: &mut SlotTable,
    mut catalog: Catalog,
    options: &ServeOptions,
) -> Result<(), Error> {
    ensure_socket_profile(&catalog, &options.profile_name)?;
    loop {
        catalog = poll_serve_once(&listener, kek, table, catalog, options)?;
    }
}

/// One accept or idle sweep. Used by the daemon loop and integration tests.
pub fn poll_serve_once(
    listener: &std::os::unix::net::UnixListener,
    kek: &AgeKek,
    table: &mut SlotTable,
    catalog: Catalog,
    options: &ServeOptions,
) -> Result<Catalog, Error> {
    if wait_for_connection(listener, SWEEP_INTERVAL)? {
        let (mut stream, _) = listener.accept()?;
        if let Err(err) = handle_serve_connection(&mut stream, kek, table, &catalog, options) {
            eprintln!("host-env-vault: {err}");
        }
        Ok(catalog)
    } else {
        tick_serve_idle(table, &options.state_dir)
    }
}

/// Idle poll handler: sweep expired leases and reload the catalog snapshot.
pub fn tick_serve_idle(table: &mut SlotTable, state_dir: &Path) -> Result<Catalog, Error> {
    table.sweep_expired(Instant::now());
    load_catalog_snapshot(state_dir)
}

fn wait_for_connection(
    listener: &std::os::unix::net::UnixListener,
    timeout: Duration,
) -> Result<bool, Error> {
    crate::serve::wait_for_socket(listener, timeout)
}

fn ensure_socket_profile<'a>(
    catalog: &'a Catalog,
    profile_name: &str,
) -> Result<&'a ProfileDefinition, Error> {
    let definition = catalog.profile(profile_name).ok_or_else(|| {
        tracing::info!(
            target: "host_env_vault::serve_cmd",
            profile = profile_name,
            "serve refuse profile not in catalog"
        );
        Error::NotInCatalog(profile_name.to_owned())
    })?;
    if !definition.socket {
        tracing::info!(
            target: "host_env_vault::serve_cmd",
            profile = profile_name,
            "serve refuse profile without socket"
        );
        return Err(Error::EntryNotAllowed {
            name: profile_name.to_owned(),
            kind: "socket",
            profile: profile_name.to_owned(),
        });
    }
    Ok(definition)
}

pub fn handle_serve_connection(
    stream: &mut std::os::unix::net::UnixStream,
    kek: &AgeKek,
    table: &mut SlotTable,
    catalog: &Catalog,
    options: &ServeOptions,
) -> Result<(), Error> {
    let definition = ensure_socket_profile(catalog, &options.profile_name)?;
    let expected_uid = definition.require_uid.ok_or_else(|| {
        Error::CatalogParse(format!(
            "profile `{}` has socket=true but no require_uid",
            options.profile_name
        ))
    })?;
    let uid = peer_uid(stream)?;
    if uid != expected_uid {
        tracing::info!(
            target: "host_env_vault::serve_cmd",
            profile = %options.profile_name,
            actual = uid,
            expected = expected_uid,
            "serve deny peer uid"
        );
        write_response(stream, &dispatch_denied())?;
        return Err(Error::PeerUid { actual: uid });
    }
    handle_connection_frames(stream, |opcode, body| {
        Ok(serve_frame(
            kek,
            table,
            catalog,
            &options.profile_name,
            &options.state_dir,
            opcode,
            body,
        ))
    })
}

fn serve_frame(
    kek: &AgeKek,
    table: &mut SlotTable,
    catalog: &Catalog,
    profile_name: &str,
    state_dir: &Path,
    opcode: u8,
    body: &[u8],
) -> Response {
    let kind = match opcode {
        OP_FETCH_ENV => Kind::Env,
        OP_FETCH_FILE => Kind::File,
        _ => return dispatch_denied(),
    };
    let entry_name = match std::str::from_utf8(body) {
        Ok(name) if !name.is_empty() && name.len() <= NAME_MAX_BYTES => name,
        _ => return dispatch_denied(),
    };
    match fetch_runtime_entry(kek, table, catalog, profile_name, state_dir, kind, entry_name) {
        Ok(bytes) => Response {
            status: ST_OK,
            body: bytes,
        },
        Err(err) => {
            tracing::info!(
                target: "host_env_vault::serve_cmd",
                profile = profile_name,
                entry = entry_name,
                kind = kind.as_str(),
                error = %err,
                "serve deny runtime entry"
            );
            dispatch_denied()
        }
    }
}

/// Open the local bundle into the serve slot and return one runtime entry.
pub fn fetch_runtime_entry(
    kek: &AgeKek,
    table: &mut SlotTable,
    catalog: &Catalog,
    profile_name: &str,
    state_dir: &Path,
    kind: Kind,
    entry_name: &str,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    validate_serve_entry(catalog, profile_name, kind, entry_name)?;
    let lease = table
        .acquire_sync(SERVE_SLOT_INDEX, SERVE_ACQUIRE_TIMEOUT)
        .map_err(map_slot_acquire)?;
    let result = (|| {
        let bundle_bytes = std::fs::read(bundle_path(state_dir, profile_name))?;
        let slot = table
            .slot_ref_mut(SERVE_SLOT_INDEX)
            .map_err(map_slot_acquire)?;
        let opened = open_profile_into_slot(catalog, &bundle_bytes, slot, lease, kek)?;
        if opened.profile != profile_name {
            return Err(Error::ProfileMismatch {
                found: opened.profile,
                expected: profile_name.to_owned(),
            });
        }
        let value = read_entry_from_slot(slot, lease, kind, entry_name)?;
        tracing::info!(
            target: "host_env_vault::serve_cmd",
            profile = profile_name,
            entry = entry_name,
            kind = kind.as_str(),
            "serve returned runtime entry"
        );
        Ok(value)
    })();
    let _ = table.release(lease);
    result
}

/// Read one entry from an already-open slot (tests and lease expiry checks).
pub fn read_entry_from_slot(
    slot: &Slot,
    lease: SlotLease,
    kind: Kind,
    entry_name: &str,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    slot.verify_lease(lease).map_err(|_| Error::RuntimeBody)?;
    let bytes = match kind {
        Kind::Env => find_secret_in_slot(slot, lease, entry_name.as_bytes())?,
        Kind::File => find_document_in_slot(slot, lease, entry_name.as_bytes())?,
    };
    Ok(Zeroizing::new(bytes))
}

fn find_secret_in_slot(
    slot: &Slot,
    lease: SlotLease,
    name: &[u8],
) -> Result<Vec<u8>, Error> {
    for index in 0..slot.secret_count() as usize {
        if slot.secret_name_bytes(index) == Some(name) {
            return slot
                .secret_bytes(index)
                .map(|value| value.to_vec())
                .ok_or(Error::RuntimeBody);
        }
    }
    let _ = lease;
    Err(Error::EntryNotAllowed {
        name: String::from_utf8_lossy(name).into_owned(),
        kind: Kind::Env.as_str(),
        profile: String::from_utf8_lossy(slot.profile_name_bytes()).into_owned(),
    })
}

fn find_document_in_slot(
    slot: &Slot,
    lease: SlotLease,
    name: &[u8],
) -> Result<Vec<u8>, Error> {
    for index in 0..slot.document_count() as usize {
        if slot.document_name_bytes(index) == Some(name) {
            return slot
                .document_bytes(index)
                .map(|value| value.to_vec())
                .ok_or(Error::RuntimeBody);
        }
    }
    let _ = lease;
    Err(Error::EntryNotAllowed {
        name: String::from_utf8_lossy(name).into_owned(),
        kind: Kind::File.as_str(),
        profile: String::from_utf8_lossy(slot.profile_name_bytes()).into_owned(),
    })
}

fn map_slot_acquire(err: SlotError) -> Error {
    Error::CatalogParse(format!("serve slot acquire: {err:?}"))
}

/// Hold an opened profile in the serve slot without releasing (tests).
#[cfg(test)]
pub fn open_profile_into_serve_slot_for_test(
    kek: &AgeKek,
    table: &mut SlotTable,
    catalog: &Catalog,
    profile_name: &str,
    state_dir: &Path,
) -> Result<SlotLease, Error> {
    let lease = table
        .try_acquire(SERVE_SLOT_INDEX, Instant::now())
        .map_err(map_slot_acquire)?;
    let bundle_bytes = std::fs::read(bundle_path(state_dir, profile_name))?;
    let slot = table
        .slot_ref_mut(SERVE_SLOT_INDEX)
        .map_err(map_slot_acquire)?;
    open_profile_into_slot(catalog, &bundle_bytes, slot, lease, kek)?;
    Ok(lease)
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod log_tests;

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::catalog::{
        parse_catalog_text, write_catalog_snapshot, DEFAULT_CATALOG_PARAMETER,
    };
    use crate::sync::DEFAULT_STATE_DIR;
    use crate::kek::AgeKek;
    use crate::catalog::SealEntry;
    use crate::local_bundle::seal_profile_in_slot;
    use crate::port::MemorySsm;
    use crate::profile::Kind;
    use crate::serve::{dispatch_denied, OP_FETCH_ENV, ST_DENIED, ST_OK};
    use crate::slot::SlotTable;
    use crate::sync::{bundle_path, sync_from_ssm, SyncOptions};

    const WORKER: &str = r#"{
      "profiles": [{
        "name": "denarius-worker",
        "inject": ["DB_PASS"],
        "runtime": ["APP_KEY"],
        "runtime_files": ["teller.key"],
        "socket": true,
        "require_uid": 33
      }]
    }"#;

    fn short_root(label: &str) -> PathBuf {
        PathBuf::from(format!("/tmp/hev6u-{label}-{}", std::process::id()))
    }

    #[test]
    fn serve_slot_is_distinct_from_render_and_sync() {
        assert_eq!(crate::sync::SYNC_SLOT_INDEX, 0);
        assert_eq!(crate::render_cmd::RENDER_SLOT_INDEX, 1);
        assert_eq!(SERVE_SLOT_INDEX, 2);
        assert!(SERVE_SLOT_INDEX < crate::slot::SLOT_COUNT);
    }

    #[test]
    fn sweep_interval_matches_lease() {
        assert_eq!(SWEEP_INTERVAL, Duration::from_millis(LEASE_MS));
    }

    #[test]
    fn bind_serve_socket_and_tick_idle_reload_catalog() {
        let root = short_root("bind");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_catalog_snapshot(&root, WORKER).unwrap();
        let options = ServeOptions::new(
            root.join("k.age"),
            root.clone(),
            root.join("run"),
            "denarius-worker",
        );
        let (listener, _) = bind_serve_socket(&options).unwrap();
        drop(listener);
        let mut table = SlotTable::new();
        let start = Instant::now();
        let lease = table.try_acquire(SERVE_SLOT_INDEX, start).unwrap();
        table.sweep_expired(start + Duration::from_millis(LEASE_MS));
        assert!(!table.slot_ref(SERVE_SLOT_INDEX).unwrap().in_use());
        let _ = lease;
        let catalog = tick_serve_idle(&mut table, &root).unwrap();
        assert!(catalog.profile("denarius-worker").unwrap().socket);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn serve_frame_fetches_runtime_file_opcode() {
        let root = short_root("op-file");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let ssm = MemorySsm::new();
        ssm.put(DEFAULT_CATALOG_PARAMETER, WORKER);
        ssm.put("/amtgard/denarius-worker/DB_PASS", "d");
        ssm.put("/amtgard/denarius-worker/APP_KEY", "k");
        ssm.put("/amtgard/denarius-worker/teller.key", "file-data");
        let kek = AgeKek::generate();
        let mut table = SlotTable::new();
        sync_from_ssm(
            &ssm,
            &kek,
            &mut table,
            &SyncOptions {
                identity_path: root.join("k.age"),
                state_dir: root.clone(),
                catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            },
        )
        .unwrap();
        let catalog = load_catalog_snapshot(&root).unwrap();
        let mut table = SlotTable::new();
        let resp = serve_frame(
            &kek,
            &mut table,
            &catalog,
            "denarius-worker",
            &root,
            crate::serve::OP_FETCH_FILE,
            b"teller.key",
        );
        assert_eq!(resp.status, ST_OK);
        assert_eq!(&resp.body[..], b"file-data");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn serve_frame_denies_oversize_entry_name() {
        let catalog = parse_catalog_text(WORKER).unwrap();
        let kek = AgeKek::generate();
        let mut table = SlotTable::new();
        let long = vec![b'n'; NAME_MAX_BYTES + 1];
        let denied = serve_frame(
            &kek,
            &mut table,
            &catalog,
            "denarius-worker",
            Path::new("/tmp"),
            OP_FETCH_ENV,
            &long,
        );
        assert_eq!(denied.status, ST_DENIED);
    }

    #[test]
    fn serve_frame_denies_bad_opcode_and_empty_entry_name() {
        let root = short_root("frame");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let ssm = MemorySsm::new();
        ssm.put(DEFAULT_CATALOG_PARAMETER, WORKER);
        ssm.put("/amtgard/denarius-worker/DB_PASS", "d");
        ssm.put("/amtgard/denarius-worker/APP_KEY", "k");
        ssm.put("/amtgard/denarius-worker/teller.key", "f");
        let kek = AgeKek::generate();
        let mut table = SlotTable::new();
        sync_from_ssm(
            &ssm,
            &kek,
            &mut table,
            &SyncOptions {
                identity_path: root.join("k.age"),
                state_dir: root.clone(),
                catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            },
        )
        .unwrap();
        let catalog = load_catalog_snapshot(&root).unwrap();
        let mut table = SlotTable::new();
        let denied = serve_frame(&kek, &mut table, &catalog, "denarius-worker", &root, 99, b"APP_KEY");
        assert_eq!(denied.status, ST_DENIED);
        let denied = serve_frame(&kek, &mut table, &catalog, "denarius-worker", &root, OP_FETCH_ENV, b"");
        assert_eq!(denied.status, ST_DENIED);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fetch_runtime_file_entry_from_local_bundle() {
        let root = short_root("file");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let catalog = parse_catalog_text(WORKER).unwrap();
        let kek = AgeKek::generate();
        let mut table = SlotTable::new();
        let lease = table.try_acquire(0, Instant::now()).unwrap();
        let entries = vec![
            SealEntry {
                name: "DB_PASS".into(),
                kind: Kind::Env,
                bytes: b"db",
            },
            SealEntry {
                name: "APP_KEY".into(),
                kind: Kind::Env,
                bytes: b"k",
            },
            SealEntry {
                name: "teller.key".into(),
                kind: Kind::File,
                bytes: b"teller-bytes",
            },
        ];
        let slot = table.slot_ref_mut(0).unwrap();
        let bytes = seal_profile_in_slot(&catalog, slot, lease, "denarius-worker", &entries, &kek).unwrap();
        std::fs::write(bundle_path(&root, "denarius-worker"), &bytes).unwrap();
        write_catalog_snapshot(&root, WORKER).unwrap();
        table.release(lease).unwrap();
        let mut serve_table = SlotTable::new();
        let file = fetch_runtime_entry(
            &kek,
            &mut serve_table,
            &catalog,
            "denarius-worker",
            &root,
            Kind::File,
            "teller.key",
        )
        .unwrap();
        assert_eq!(&file[..], b"teller-bytes");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bind_refuses_unknown_profile_and_non_socket() {
        let root = short_root("refuse");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_catalog_snapshot(
            &root,
            r#"{"profiles":[{"name":"denarius-web","inject":["DB_PASS"],"runtime":[],"socket":false}]}"#,
        )
        .unwrap();
        let options = ServeOptions::new(root.join("k"), root.clone(), root.join("run"), "missing");
        assert!(bind_serve_socket(&options).is_err());
        let options = ServeOptions::new(root.join("k"), root.clone(), root.join("run"), "denarius-web");
        assert!(bind_serve_socket(&options).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn serve_options_default_state_dir() {
        let opts = ServeOptions::with_default_state_dir(
            PathBuf::from("/etc/host-env-vault/kek.age"),
            PathBuf::from("/run/host-env-vault"),
            "denarius-worker",
        );
        assert_eq!(opts.state_dir, PathBuf::from(DEFAULT_STATE_DIR));
    }

    #[test]
    fn poll_serve_once_accepts_one_connection() {
        use std::os::unix::net::UnixStream;
        use std::thread;

        let root = short_root("poll-in");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let ssm = MemorySsm::new();
        ssm.put(DEFAULT_CATALOG_PARAMETER, WORKER);
        ssm.put("/amtgard/denarius-worker/DB_PASS", "d");
        ssm.put("/amtgard/denarius-worker/APP_KEY", "k");
        ssm.put("/amtgard/denarius-worker/teller.key", "file-data");
        let kek = AgeKek::generate();
        let mut table = SlotTable::new();
        sync_from_ssm(
            &ssm,
            &kek,
            &mut table,
            &SyncOptions {
                identity_path: root.join("k.age"),
                state_dir: root.clone(),
                catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            },
        )
        .unwrap();
        let uid = unsafe { libc::getuid() };
        let catalog_text = WORKER.replace("\"require_uid\": 33", &format!("\"require_uid\": {uid}"));
        write_catalog_snapshot(&root, &catalog_text).unwrap();
        let options = ServeOptions::new(
            root.join("k.age"),
            root.clone(),
            root.join("run"),
            "denarius-worker",
        );
        let (listener, catalog) = bind_serve_socket(&options).unwrap();
        let path = root.join("run").join("sockets").join("denarius-worker.sock");
        let server = thread::spawn(move || {
            poll_serve_once(&listener, &kek, &mut SlotTable::new(), catalog, &options).unwrap();
        });
        thread::sleep(Duration::from_millis(30));
        let mut client = UnixStream::connect(&path).unwrap();
        let resp = crate::serve::exchange(&mut client, OP_FETCH_ENV, b"APP_KEY").unwrap();
        assert_eq!(resp.status, ST_OK);
        drop(client);
        server.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn poll_serve_once_times_out_and_sweeps() {
        let root = short_root("poll");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_catalog_snapshot(&root, WORKER).unwrap();
        let options = ServeOptions::new(
            root.join("k.age"),
            root.clone(),
            root.join("run"),
            "denarius-worker",
        );
        let (listener, catalog) = bind_serve_socket(&options).unwrap();
        let kek = AgeKek::generate();
        let mut table = SlotTable::new();
        let _ = poll_serve_once(&listener, &kek, &mut table, catalog, &options).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fetch_errors_when_runtime_entry_missing_from_bundle() {
        let root = short_root("missing");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let catalog = parse_catalog_text(WORKER).unwrap();
        let kek = AgeKek::generate();
        let mut table = SlotTable::new();
        let lease = table.try_acquire(0, Instant::now()).unwrap();
        let entries = vec![SealEntry {
            name: "APP_KEY".into(),
            kind: Kind::Env,
            bytes: b"k",
        }];
        let slot = table.slot_ref_mut(0).unwrap();
        let bytes =
            seal_profile_in_slot(&catalog, slot, lease, "denarius-worker", &entries, &kek).unwrap();
        std::fs::write(bundle_path(&root, "denarius-worker"), &bytes).unwrap();
        write_catalog_snapshot(&root, WORKER).unwrap();
        table.release(lease).unwrap();
        let mut serve_table = SlotTable::new();
        assert!(matches!(
            fetch_runtime_entry(
                &kek,
                &mut serve_table,
                &catalog,
                "denarius-worker",
                &root,
                Kind::Env,
                "APP_KEY",
            ),
            Ok(_)
        ));
        assert!(matches!(
            fetch_runtime_entry(
                &kek,
                &mut serve_table,
                &catalog,
                "denarius-worker",
                &root,
                Kind::Env,
                "teller.key",
            ),
            Err(Error::EntryNotAllowed { .. })
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn serve_deny_log_emits_on_fetch_failure() {
        let catalog = parse_catalog_text(WORKER).unwrap();
        let root = short_root("deny-log");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_catalog_snapshot(&root, WORKER).unwrap();
        let kek = AgeKek::generate();
        let mut table = SlotTable::new();
        let resp = serve_frame(
            &kek,
            &mut table,
            &catalog,
            "denarius-worker",
            &root,
            OP_FETCH_ENV,
            b"APP_KEY",
        );
        assert_eq!(resp.status, dispatch_denied().status);
        std::fs::remove_dir_all(root).unwrap();
    }
}
