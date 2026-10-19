use serial_test::serial;
use std::path::PathBuf;

use crate::application::manifest::{default_manifests_dir, write_manifest_for_profile};
use crate::application::sync::{load_or_create_identity, sync_from_ssm, SyncOptions};
use crate::catalog::{parse_catalog_text, DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};
use crate::config::SyncSourceKind;
use crate::core::slot::{SlotTable, SECRET_MAX_BYTES};
use crate::ports::MemorySsm;
use crate::testing::log_test_capture::capture_info_logs;
use crate::vault::kek::AgeKek;

const WEB: &str = r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#;

fn temp_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("hev-sync-log-{label}-{}-{id}", std::process::id()))
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
    std::fs::create_dir_all(&state_dir).unwrap();
    write_manifest_for_profile(
        &default_manifests_dir(&state_dir),
        parse_catalog_text(WEB).unwrap().profile("app-web").unwrap(),
    )
    .unwrap();
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB);
    ssm.put("/host-env-vault/app-web/DB_PASS", "secret");
    let kek = AgeKek::generate();
    let text = capture_info_logs(|| {
        let mut table = SlotTable::new();
        let options = SyncOptions {
            identity_path: state_dir.join("kek.age"),
            state_dir: state_dir.clone(),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
            source: SyncSourceKind::Ssm,
            local_secrets_dir: None,
            manifests_dir: None,
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
    std::fs::create_dir_all(&state_dir).unwrap();
    write_manifest_for_profile(
        &default_manifests_dir(&state_dir),
        parse_catalog_text(WEB).unwrap().profile("app-web").unwrap(),
    )
    .unwrap();
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB);
    let kek = AgeKek::generate();
    let text = capture_info_logs(|| {
        let mut table = SlotTable::new();
        let options = SyncOptions {
            identity_path: state_dir.join("kek.age"),
            state_dir: state_dir.clone(),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
            source: SyncSourceKind::Ssm,
            local_secrets_dir: None,
            manifests_dir: None,
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
    std::fs::create_dir_all(&state_dir).unwrap();
    write_manifest_for_profile(
        &default_manifests_dir(&state_dir),
        parse_catalog_text(WEB).unwrap().profile("app-web").unwrap(),
    )
    .unwrap();
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB);
    let huge = "x".repeat(SECRET_MAX_BYTES + 1);
    ssm.put("/host-env-vault/app-web/DB_PASS", huge);
    let kek = AgeKek::generate();
    let text = capture_info_logs(|| {
        let mut table = SlotTable::new();
        let options = SyncOptions {
            identity_path: state_dir.join("kek.age"),
            state_dir: state_dir.clone(),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
            source: SyncSourceKind::Ssm,
            local_secrets_dir: None,
            manifests_dir: None,
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
