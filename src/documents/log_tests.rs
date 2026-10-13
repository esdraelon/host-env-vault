use std::sync::{Arc, Mutex};

use crate::catalog::parse_catalog_text;
use crate::documents::pull_profile_documents;
use crate::port::MemoryS3;
use crate::slot::DOCUMENT_MAX_BYTES;
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

#[test]
fn log_reject_oversize_s3_object() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["big.conf"]}]}"#,
    )
    .unwrap();
    let nginx = catalog.profile("nginx").unwrap();
    let s3 = MemoryS3::new();
    s3.put("big.conf", &vec![b'x'; DOCUMENT_MAX_BYTES + 1]);
    let joined = capture_logs(|| {
        let _ = pull_profile_documents(&s3, "", nginx);
    });
    assert!(joined.contains("documents reject oversize s3 object"));
}

#[test]
fn log_reject_secret_shaped_s3_key() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["oauth-private.key"]}]}"#,
    )
    .unwrap();
    let nginx = catalog.profile("nginx").unwrap();
    let s3 = MemoryS3::new();
    let joined = capture_logs(|| {
        let _ = pull_profile_documents(&s3, "", nginx);
    });
    assert!(joined.contains("documents reject secret-shaped s3 key"));
}

#[test]
fn log_loaded_s3_object() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["denarius.env"]}]}"#,
    )
    .unwrap();
    let nginx = catalog.profile("nginx").unwrap();
    let s3 = MemoryS3::new();
    s3.put("denarius.env", b"APP_ENV=prod\n");
    let joined = capture_logs(|| {
        pull_profile_documents(&s3, "", nginx).unwrap();
    });
    assert!(joined.contains("documents loaded s3 object"));
}
