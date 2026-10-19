use std::fs;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use crate::application::serve::{
    fetch_runtime_entry, handle_serve_connection, open_profile_into_serve_slot_for_test,
    read_entry_from_slot, ServeOptions, SERVE_SLOT_INDEX,
};
use crate::application::manifest::seed_manifests_for_catalog_text;
use crate::application::sync::{sync_from_ssm, SyncOptions, SYNC_SLOT_INDEX};
use crate::catalog::{DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};
use crate::core::error::Error;
use crate::core::slot::{SlotTable, LEASE_MS};
use crate::legacy::profile::Kind;
use crate::legacy::serve::{bind_runtime_socket, exchange, OP_FETCH_ENV, ST_DENIED, ST_OK};
use crate::ports::{MemorySsm, SsmPort};
use crate::vault::kek::AgeKek;

const WORKER_CATALOG: &str = r#"{
  "profiles": [{
    "name": "app-worker",
    "inject": ["DB_PASS", "WEBHOOK_HMAC"],
    "runtime": ["APP_KEY", "API_SECRET"],
    "inject_files": [],
    "runtime_files": ["client.key"],
    "socket": true,
    "require_uid": 33
  }]
}"#;

fn temp_root(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!("/tmp/hev6-{label}-{}-{id}", std::process::id()))
}

fn seed_worker_ssm(ssm: &MemorySsm) {
    ssm.put(DEFAULT_CATALOG_PARAMETER, WORKER_CATALOG);
    ssm.put("/host-env-vault/app-worker/DB_PASS", "db");
    ssm.put("/host-env-vault/app-worker/WEBHOOK_HMAC", "whsec");
    ssm.put("/host-env-vault/app-worker/APP_KEY", "app-key-runtime");
    ssm.put("/host-env-vault/app-worker/API_SECRET", "sk-runtime");
    ssm.put("/host-env-vault/app-worker/client.key", "client-bytes");
}

fn sync_worker_vault(root: &PathBuf) -> (AgeKek, PathBuf) {
    let state_dir = root.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    seed_manifests_for_catalog_text(&state_dir, WORKER_CATALOG).unwrap();
    let ssm = MemorySsm::new();
    seed_worker_ssm(&ssm);
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: root.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        source: crate::config::SyncSourceKind::Ssm,
        local_secrets_dir: None,
        manifests_dir: None,
        s3_prefix: None,
    };
    sync_from_ssm(&ssm, &kek, &mut table, &options).unwrap();
    assert_eq!(
        table.slot_ref(SYNC_SLOT_INDEX).unwrap().secret_count(),
        0,
        "sync must release its slot"
    );
    (kek, state_dir)
}

#[test]
fn serve_returns_runtime_entry_from_local_bundle_without_ssm() {
    let root = temp_root("fetch");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let (kek, state_dir) = sync_worker_vault(&root);
    let catalog = crate::catalog::load_catalog_snapshot(&state_dir).unwrap();
    let mut table = SlotTable::new();

    struct PanicSsm;
    impl SsmPort for PanicSsm {
        fn get_parameter(&self, name: &str) -> Result<String, crate::ports::SsmError> {
            panic!("serve must not call SSM, got {name}");
        }
    }
    let _guard = PanicSsm;

    let value = fetch_runtime_entry(
        &kek,
        &mut table,
        &catalog,
        "app-worker",
        &state_dir,
        Kind::Env,
        "APP_KEY",
    )
    .unwrap();
    assert_eq!(&value[..], b"app-key-runtime");
    assert_eq!(
        table.slot_ref(SERVE_SLOT_INDEX).unwrap().secret_count(),
        0,
        "serve releases and wipes the slot"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn serve_refuses_bundle_profile_mismatch() {
    let root = temp_root("profile-mismatch");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let (kek, state_dir) = sync_worker_vault(&root);
    let extended_catalog = r#"{
  "profiles": [
    {"name":"app-web","inject":["DB_PASS"],"runtime":[]},
    {"name":"app-worker","inject":["DB_PASS","WEBHOOK_HMAC"],"runtime":["APP_KEY","API_SECRET"],"inject_files":[],"runtime_files":["client.key"],"socket":true,"require_uid":33}
  ]
}"#;
    fs::write(state_dir.join("catalog.json"), extended_catalog.as_bytes()).unwrap();
    let catalog = crate::catalog::load_catalog_snapshot(&state_dir).unwrap();
    let bundle = crate::vault::bundle::seal_bytes(
        "app-web",
        vec![crate::vault::bundle::Entry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: zeroize::Zeroizing::new(b"wrong-profile".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    fs::write(
        crate::application::sync::bundle_path(&state_dir, "app-worker"),
        bundle,
    )
    .unwrap();
    let mut table = SlotTable::new();
    assert!(matches!(
        fetch_runtime_entry(
            &kek,
            &mut table,
            &catalog,
            "app-worker",
            &state_dir,
            Kind::Env,
            "APP_KEY",
        ),
        Err(Error::ProfileMismatch { .. })
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn serve_denies_inject_only_entry_on_worker_socket() {
    let root = temp_root("wrong-entry");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let (kek, state_dir) = sync_worker_vault(&root);
    let catalog = crate::catalog::load_catalog_snapshot(&state_dir).unwrap();
    let mut table = SlotTable::new();
    assert!(matches!(
        fetch_runtime_entry(
            &kek,
            &mut table,
            &catalog,
            "app-worker",
            &state_dir,
            Kind::Env,
            "DB_PASS",
        ),
        Err(Error::EntryNotAllowed { .. })
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn serve_denies_peer_uid_mismatch_on_socket() {
    let root = temp_root("uid");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let (kek, state_dir) = sync_worker_vault(&root);
    let actual_uid = unsafe { libc::getuid() };
    let wrong_uid = if actual_uid == u32::MAX {
        u32::MAX - 1
    } else {
        actual_uid + 1
    };
    let catalog_text = WORKER_CATALOG.replace(
        "\"require_uid\": 33",
        &format!("\"require_uid\": {wrong_uid}"),
    );
    fs::write(state_dir.join("catalog.json"), catalog_text.as_bytes()).unwrap();
    let catalog = crate::catalog::load_catalog_snapshot(&state_dir).unwrap();
    let options = ServeOptions::new(
        root.join("kek.age"),
        state_dir,
        root.join("run"),
        "app-worker",
    );
    let mut table = SlotTable::new();
    let (mut server, mut client) = UnixStream::pair().unwrap();

    let server = thread::spawn(move || {
        let err =
            handle_serve_connection(&mut server, &kek, &mut table, &catalog, &options).unwrap_err();
        assert!(matches!(err, Error::PeerUid { .. }));
    });

    let denied = exchange(&mut client, OP_FETCH_ENV, b"APP_KEY").unwrap();
    assert_eq!(denied.status, ST_DENIED);
    drop(client);
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn serve_accepts_matching_peer_uid_and_returns_runtime_secret() {
    let root = temp_root("uid-ok");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let (kek, state_dir) = sync_worker_vault(&root);
    let runtime_dir = root.join("run");
    let mut catalog_text = WORKER_CATALOG.to_owned();
    let uid = unsafe { libc::getuid() };
    catalog_text = catalog_text.replace("\"require_uid\": 33", &format!("\"require_uid\": {uid}"));
    fs::write(state_dir.join("catalog.json"), catalog_text.as_bytes()).unwrap();
    let catalog = crate::catalog::load_catalog_snapshot(&state_dir).unwrap();
    let listener = bind_runtime_socket(&runtime_dir, "app-worker").unwrap();
    let path = runtime_dir.join("sockets").join("app-worker.sock");
    let options = ServeOptions::new(
        root.join("kek.age"),
        state_dir,
        runtime_dir,
        "app-worker",
    );
    let mut table = SlotTable::new();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        handle_serve_connection(&mut stream, &kek, &mut table, &catalog, &options).unwrap();
    });

    let mut client = UnixStream::connect(&path).unwrap();
    let response = exchange(&mut client, OP_FETCH_ENV, b"APP_KEY").unwrap();
    assert_eq!(response.status, ST_OK);
    assert_eq!(&response.body[..], b"app-key-runtime");
    drop(client);
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn lease_sweep_wipes_serve_slot_before_late_read() {
    let root = temp_root("lease");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let (kek, state_dir) = sync_worker_vault(&root);
    let catalog = crate::catalog::load_catalog_snapshot(&state_dir).unwrap();
    let mut table = SlotTable::new();
    let lease = open_profile_into_serve_slot_for_test(
        &kek,
        &mut table,
        &catalog,
        "app-worker",
        &state_dir,
    )
    .unwrap();
    let slot = table.slot_ref(SERVE_SLOT_INDEX).unwrap();
    assert!(read_entry_from_slot(slot, lease, Kind::Env, "APP_KEY").is_ok());
    thread::sleep(Duration::from_millis(LEASE_MS + 100));
    table.sweep_expired(Instant::now());
    let slot = table.slot_ref(SERVE_SLOT_INDEX).unwrap();
    assert!(matches!(
        read_entry_from_slot(slot, lease, Kind::Env, "APP_KEY"),
        Err(Error::RuntimeBody)
    ));
    assert!(!slot.in_use());
    fs::remove_dir_all(root).unwrap();
}
