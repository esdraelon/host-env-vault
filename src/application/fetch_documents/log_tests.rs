use serial_test::serial;
use std::path::PathBuf;

use crate::application::fetch_documents::{fetch_profile_documents, FetchDocumentsOptions};
use crate::catalog::write_catalog_snapshot;
use crate::core::slot::SlotTable;
use crate::ports::MemoryS3;
use crate::testing::log_test_capture::capture_info_logs;

fn temp_state_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("hev-fetch-log-{label}-{}-{id}", std::process::id()))
}

#[serial]
#[test]
fn log_fetch_documents_refuse_profile_not_in_catalog() {
    let state_dir = temp_state_dir("missing-profile");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    write_catalog_snapshot(
        &state_dir,
        r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":[]}]}"#,
    )
    .unwrap();
    let s3 = MemoryS3::new();
    let mut table = SlotTable::new();
    let options = FetchDocumentsOptions::new(state_dir.clone(), "prefix", "missing");
    let joined = capture_info_logs(|| {
        let _ = fetch_profile_documents(&s3, &mut table, &options);
    });
    assert!(joined.contains("fetch documents refuse profile not in catalog"));
    let _ = std::fs::remove_dir_all(&state_dir);
}
