use std::path::PathBuf;

use crate::application::hydrate::{hydrate_gh_from_vault, HydrateGhOptions, GITHUB_PROFILE};
use crate::application::sync::SYNC_SLOT_INDEX;
use crate::catalog::{parse_catalog_text, write_catalog_snapshot, SealEntry};
use crate::core::slot::SlotTable;
use crate::legacy::profile::Kind;
use crate::ports::MemoryGh;
use crate::testing::log_test_capture::capture_info_logs;
use crate::vault::kek::AgeKek;
use crate::vault::local_bundle::seal_profile_in_slot;
use serial_test::serial;

const GITHUB_CATALOG: &str = r#"{"profiles":[{"name":"github","inject":[],"runtime":["esdraelon","megiddo"],"github_active_user":"esdraelon"}]}"#;

fn temp_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-hydrate-log-{label}-{}-{id}",
        std::process::id()
    ))
}

fn seal_github(state_dir: &PathBuf, kek: &AgeKek) {
    let catalog = parse_catalog_text(GITHUB_CATALOG).unwrap();
    let mut table = SlotTable::new();
    let lease = table
        .try_acquire(SYNC_SLOT_INDEX, std::time::Instant::now())
        .unwrap();
    let slot = table.slot_ref_mut(SYNC_SLOT_INDEX).unwrap();
    let entries = [SealEntry {
        name: "esdraelon".into(),
        kind: Kind::Env,
        bytes: b"tok",
    }];
    let bundle =
        seal_profile_in_slot(&catalog, slot, lease, GITHUB_PROFILE, &entries, kek).unwrap();
    let _ = table.release(lease);
    std::fs::write(
        crate::application::sync::bundle_path(state_dir, GITHUB_PROFILE),
        bundle,
    )
    .unwrap();
}

#[serial]
#[test]
fn log_hydrate_refuse_profile_not_in_catalog() {
    let state_dir = temp_dir("refuse-profile");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    write_catalog_snapshot(
        &state_dir,
        r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[]}]}"#,
    )
    .unwrap();
    let text = capture_info_logs(|| {
        let gh = MemoryGh::new();
        let kek = AgeKek::generate();
        let mut table = SlotTable::new();
        let options = HydrateGhOptions::new(state_dir.join("kek.age"), state_dir.clone());
        let _ = hydrate_gh_from_vault(&gh, &kek, &mut table, &options);
    });
    assert!(
        text.contains("hydrate refuse profile not in catalog"),
        "logs: {text}"
    );
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[serial]
#[test]
fn log_hydrate_refuse_missing_github_active_user() {
    let state_dir = temp_dir("refuse-active");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    write_catalog_snapshot(
        &state_dir,
        r#"{"profiles":[{"name":"github","inject":[],"runtime":["esdraelon"]}]}"#,
    )
    .unwrap();
    let kek = AgeKek::generate();
    seal_github(&state_dir, &kek);
    let text = capture_info_logs(|| {
        let gh = MemoryGh::new();
        let mut table = SlotTable::new();
        let options = HydrateGhOptions::new(state_dir.join("kek.age"), state_dir.clone());
        let _ = hydrate_gh_from_vault(&gh, &kek, &mut table, &options);
    });
    assert!(
        text.contains("hydrate refuse missing github active user"),
        "logs: {text}"
    );
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[serial]
#[test]
fn log_hydrate_gh_logged_in_and_switched() {
    let state_dir = temp_dir("success");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    write_catalog_snapshot(&state_dir, GITHUB_CATALOG).unwrap();
    let kek = AgeKek::generate();
    let catalog = parse_catalog_text(GITHUB_CATALOG).unwrap();
    let mut table = SlotTable::new();
    let lease = table
        .try_acquire(SYNC_SLOT_INDEX, std::time::Instant::now())
        .unwrap();
    let slot = table.slot_ref_mut(SYNC_SLOT_INDEX).unwrap();
    let entries = [
        SealEntry {
            name: "esdraelon".into(),
            kind: Kind::Env,
            bytes: b"a",
        },
        SealEntry {
            name: "megiddo".into(),
            kind: Kind::Env,
            bytes: b"b",
        },
    ];
    let bundle =
        seal_profile_in_slot(&catalog, slot, lease, GITHUB_PROFILE, &entries, &kek).unwrap();
    let _ = table.release(lease);
    std::fs::write(
        crate::application::sync::bundle_path(&state_dir, GITHUB_PROFILE),
        bundle,
    )
    .unwrap();
    let text = capture_info_logs(|| {
        let gh = MemoryGh::new();
        let mut table = SlotTable::new();
        let options = HydrateGhOptions::new(state_dir.join("kek.age"), state_dir.clone());
        hydrate_gh_from_vault(&gh, &kek, &mut table, &options).unwrap();
    });
    assert!(
        text.contains("hydrate gh logged in account"),
        "logs: {text}"
    );
    assert!(
        text.contains("hydrate gh switched active user"),
        "logs: {text}"
    );
    let _ = std::fs::remove_dir_all(&state_dir);
}
