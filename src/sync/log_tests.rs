use std::path::PathBuf;
use serial_test::serial;

use crate::catalog::DEFAULT_CATALOG_PARAMETER;
use crate::kek::AgeKek;
use crate::log_test_capture::capture_info_logs;
use crate::port::MemorySsm;
use crate::slot::{SlotTable, SECRET_MAX_BYTES};
use crate::sync::{load_or_create_identity, sync_from_ssm, SyncOptions};

const WEB: &str = r#"{"profiles":[{"name":"denarius-web","inject":["DB_PASS"],"runtime":[]}]}"#;

fn temp_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-sync-log-{label}-{}-{id}",
        std::process::id()
    ))
}

#[serial]
#[test]
fn log_sync_created_host_identity() {
    let state_dir = temp_dir("identity-log");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    let path = state_dir.join("kek.age");
    let text = capture_info_logs(|| {
        let _ = load_or_create_identity(&path).unwrap();
    });
    assert!(text.contains("sync created host identity"), "logs: {text}");
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[serial]
#[test]
fn log_sync_catalog_loaded_and_sealed() {
    let state_dir = temp_dir("catalog-sealed");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB);
    ssm.put("/amtgard/denarius-web/DB_PASS", "secret");
    let kek = AgeKek::generate();
    let text = capture_info_logs(|| {
        let mut table = SlotTable::new();
        let options = SyncOptions {
            identity_path: state_dir.join("kek.age"),
            state_dir: state_dir.clone(),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            s3_prefix: None,
        };
        sync_from_ssm(&ssm, &kek, &mut table, &options).unwrap();
    });
    assert!(text.contains("sync catalog loaded"), "logs: {text}");
    assert!(
        text.contains("sync profile sealed replacing bundle"),
        "logs: {text}"
    );
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[serial]
#[test]
fn log_sync_profile_failed_keeping_bundle() {
    let state_dir = temp_dir("failed-keep");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB);
    let kek = AgeKek::generate();
    let text = capture_info_logs(|| {
        let mut table = SlotTable::new();
        let options = SyncOptions {
            identity_path: state_dir.join("kek.age"),
            state_dir: state_dir.clone(),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            s3_prefix: None,
        };
        let _ = sync_from_ssm(&ssm, &kek, &mut table, &options);
    });
    assert!(
        text.contains("sync profile failed keeping bundle"),
        "logs: {text}"
    );
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[serial]
#[test]
fn log_sync_reject_oversize_parameter() {
    let state_dir = temp_dir("oversize");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB);
    let huge = "x".repeat(SECRET_MAX_BYTES + 1);
    ssm.put("/amtgard/denarius-web/DB_PASS", huge);
    let kek = AgeKek::generate();
    let text = capture_info_logs(|| {
        let mut table = SlotTable::new();
        let options = SyncOptions {
            identity_path: state_dir.join("kek.age"),
            state_dir: state_dir.clone(),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            s3_prefix: None,
        };
        let _ = sync_from_ssm(&ssm, &kek, &mut table, &options);
    });
    assert!(
        text.contains("sync reject oversize parameter"),
        "logs: {text}"
    );
    let _ = std::fs::remove_dir_all(&state_dir);
}
