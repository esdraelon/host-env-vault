use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::catalog::write_catalog_snapshot;
use crate::fetch_documents_cmd::{fetch_profile_documents, FetchDocumentsOptions};
use crate::port::MemoryS3;
use crate::slot::SlotTable;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

fn capture_logs<F: FnOnce()>(test: F) -> String {
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = lines.clone();
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .without_time()
        .with_target(true)
        .with_writer(move || LogWriter(sink.clone()))
        .with_filter(tracing_subscriber::filter::LevelFilter::INFO);
    let _guard = tracing_subscriber::registry().with(layer).set_default();
    test();
    let joined = lines.lock().unwrap().concat();
    joined
}

struct LogWriter(Arc<Mutex<Vec<String>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(buf).to_string());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn temp_state_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-fetch-log-{label}-{}-{id}",
        std::process::id()
    ))
}

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
    let joined = capture_logs(|| {
        let _ = fetch_profile_documents(&s3, &mut table, &options);
    });
    assert!(joined.contains("fetch documents refuse profile not in catalog"));
    let _ = std::fs::remove_dir_all(&state_dir);
}
