use std::fs;
use serial_test::serial;
use std::path::PathBuf;

use crate::catalog::{
    load_catalog_snapshot, parse_catalog_text, write_catalog_snapshot, DEFAULT_CATALOG_PARAMETER,
};
use crate::kek::AgeKek;
use crate::log_test_capture::capture_info_logs;
use crate::port::MemorySsm;
use crate::profile::Kind;
use crate::serve_cmd::{bind_serve_socket, fetch_runtime_entry, ServeOptions};
use crate::slot::SlotTable;
use crate::sync::{sync_from_ssm, SyncOptions};

const WORKER: &str = r#"{
  "profiles": [{
    "name": "denarius-worker",
    "inject": ["DB_PASS"],
    "runtime": ["APP_KEY"],
    "socket": true,
    "require_uid": 33
  }]
}"#;

fn temp_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-serve-log-{label}-{}-{id}",
        std::process::id()
    ))
}

#[serial]
#[test]
fn log_serve_deny_runtime_entry_and_return_success() {
    let root = temp_dir("deny-ok");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let state_dir = root.join("state");
    fs::create_dir(&state_dir).unwrap();
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WORKER);
    ssm.put("/amtgard/denarius-worker/DB_PASS", "db");
    ssm.put("/amtgard/denarius-worker/APP_KEY", "key");
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    sync_from_ssm(
        &ssm,
        &kek,
        &mut table,
        &SyncOptions {
            identity_path: root.join("kek.age"),
            state_dir: state_dir.clone(),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            s3_prefix: None,
        },
    )
    .unwrap();
    let catalog = load_catalog_snapshot(&state_dir).unwrap();

    let deny_text = capture_info_logs(|| {
        let mut t = SlotTable::new();
        let _ = fetch_runtime_entry(
            &kek,
            &mut t,
            &catalog,
            "denarius-worker",
            &state_dir,
            Kind::Env,
            "DB_PASS",
        );
    });
    assert!(
        deny_text.contains("catalog refuse serve entry"),
        "{deny_text}"
    );

    let ok_text = capture_info_logs(|| {
        let mut t = SlotTable::new();
        let _ = fetch_runtime_entry(
            &kek,
            &mut t,
            &catalog,
            "denarius-worker",
            &state_dir,
            Kind::Env,
            "APP_KEY",
        );
    });
    assert!(
        ok_text.contains("serve returned runtime entry"),
        "{ok_text}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[serial]
#[test]
fn log_serve_refuse_profile_without_socket() {
    let catalog_text =
        r#"{"profiles":[{"name":"denarius-web","inject":["DB_PASS"],"runtime":[],"socket":false}]}"#;
    let _catalog = parse_catalog_text(catalog_text).unwrap();
    let root = temp_dir("nosock");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    fs::create_dir_all(&root).unwrap();
    write_catalog_snapshot(&root, catalog_text).unwrap();
    let options = ServeOptions::new(
        root.join("kek.age"),
        root.clone(),
        root.join("run"),
        "denarius-web",
    );
    let text = capture_info_logs(|| {
        assert!(matches!(
            bind_serve_socket(&options),
            Err(crate::error::Error::EntryNotAllowed { .. })
        ));
    });
    assert!(
        text.contains("serve refuse profile without socket"),
        "{text}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[serial]
#[test]
fn log_serve_deny_peer_uid() {
    use std::os::unix::net::UnixStream;

    let root = temp_dir("uid-log");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let state_dir = root.join("state");
    fs::create_dir(&state_dir).unwrap();
    write_catalog_snapshot(&state_dir, WORKER).unwrap();
    let catalog = load_catalog_snapshot(&state_dir).unwrap();
    let kek = AgeKek::generate();
    let options = ServeOptions::new(
        root.join("kek.age"),
        state_dir,
        root.join("run"),
        "denarius-worker",
    );
    let mut table = SlotTable::new();
    let (mut server, client) = UnixStream::pair().unwrap();
    drop(client);

    let text = capture_info_logs(|| {
        let _ = crate::serve_cmd::handle_serve_connection(
            &mut server,
            &kek,
            &mut table,
            &catalog,
            &options,
        );
    });
    assert!(text.contains("serve deny peer uid"));
    fs::remove_dir_all(root).unwrap();
}
