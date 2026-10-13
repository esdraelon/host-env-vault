use std::path::PathBuf;
use serial_test::serial;

use crate::catalog::write_catalog_snapshot;
use crate::kek::AgeKek;
use crate::log_test_capture::capture_info_logs;
use crate::port::MemorySsm;
use crate::profile::Kind;
use crate::render_cmd::{render_from_vault, RenderOptions};
use crate::slot::SlotTable;
use crate::sync::sync_catalog_from_text;

const WORKER: &str = r#"{"profiles":[{"name":"denarius-worker","inject":["DB_PASS"],"runtime":["APP_KEY"],"inject_files":[],"runtime_files":[]}]}"#;

fn temp_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-render-log-{label}-{}-{id}",
        std::process::id()
    ))
}

#[serial]
#[test]
fn log_render_skips_runtime_entries_and_writes_destination() {
    let root = temp_dir("runtime-skip");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let state_dir = root.join("state");
    let dest = root.join("dest");
    let ssm = MemorySsm::new();
    ssm.put(crate::catalog::DEFAULT_CATALOG_PARAMETER, WORKER);
    ssm.put("/amtgard/denarius-worker/DB_PASS", "db");
    ssm.put("/amtgard/denarius-worker/APP_KEY", "key");
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    sync_catalog_from_text(WORKER, &ssm, None, None, &kek, &mut table, &state_dir).unwrap();

    let text = capture_info_logs(|| {
        render_from_vault(
            &kek,
            &mut table,
            "denarius-worker",
            &RenderOptions::new(root.join("kek.age"), state_dir, dest, None),
        )
        .unwrap();
    });
    assert!(
        text.contains("render inject only skipping runtime entries"),
        "logs: {text}"
    );
    assert!(
        text.contains("render wrote inject entries to destination"),
        "logs: {text}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[serial]
#[test]
fn log_render_refuses_unknown_profile() {
    let root = temp_dir("unknown-profile");
    let _ = std::fs::remove_dir_all(&root);
    let state_dir = root.join("state");
    write_catalog_snapshot(
        &state_dir,
        r#"{"profiles":[{"name":"denarius-web","inject":["DB_PASS"],"runtime":[]}]}"#,
    )
    .unwrap();
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();

    let text = capture_info_logs(|| {
        let _ = render_from_vault(
            &kek,
            &mut table,
            "missing-profile",
            &RenderOptions::new(root.join("k"), state_dir, root.join("dest"), None),
        );
    });
    assert!(
        text.contains("render refuse profile not in catalog"),
        "logs: {text}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[serial]
#[test]
fn log_render_does_not_skip_when_all_entries_are_inject() {
    let root = temp_dir("inject-only");
    let _ = std::fs::remove_dir_all(&root);
    let state_dir = root.join("state");
    let dest = root.join("dest");
    let catalog =
        r#"{"profiles":[{"name":"p","inject":["DB_PASS"],"runtime":[],"inject_files":[],"runtime_files":[]}]}"#;
    write_catalog_snapshot(&state_dir, catalog).unwrap();
    let kek = AgeKek::generate();
    let bundle = crate::bundle::seal_bytes(
        "p",
        vec![crate::bundle::Entry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: zeroize::Zeroizing::new(b"x".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    std::fs::write(crate::sync::bundle_path(&state_dir, "p"), bundle).unwrap();
    let mut table = SlotTable::new();

    let text = capture_info_logs(|| {
        render_from_vault(
            &kek,
            &mut table,
            "p",
            &RenderOptions::new(root.join("k"), state_dir, dest, None),
        )
        .unwrap();
    });
    assert!(
        !text.contains("render inject only skipping runtime entries"),
        "logs: {text}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[serial]
#[test]
fn log_local_bundle_open_during_render() {
    let root = temp_dir("open-slot");
    let _ = std::fs::remove_dir_all(&root);
    let state_dir = root.join("state");
    let dest = root.join("dest");
    let catalog =
        r#"{"profiles":[{"name":"p","inject":["DB_PASS"],"runtime":[],"inject_files":[],"runtime_files":[]}]}"#;
    write_catalog_snapshot(&state_dir, catalog).unwrap();
    let kek = AgeKek::generate();
    let bundle = crate::bundle::seal_bytes(
        "p",
        vec![crate::bundle::Entry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: zeroize::Zeroizing::new(b"x".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    std::fs::write(crate::sync::bundle_path(&state_dir, "p"), bundle).unwrap();
    let mut table = SlotTable::new();

    let text = capture_info_logs(|| {
        render_from_vault(
            &kek,
            &mut table,
            "p",
            &RenderOptions::new(root.join("k"), state_dir, dest, None),
        )
        .unwrap();
    });
    assert!(
        text.contains("local bundle open into slot"),
        "logs: {text}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
