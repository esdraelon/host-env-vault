use super::{parse_catalog_text, validate_seal_entries, validate_serve_entry, SealEntry};
use crate::profile::Kind;
use std::sync::{Arc, Mutex};
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
fn log_catalog_parse_failure() {
    let text = capture_logs(|| {
        let _ = parse_catalog_text("{ not json");
    });
    assert!(
        text.contains("catalog parse failed"),
        "logs: {text}"
    );
}

#[test]
fn log_catalog_refuse_seal_entry() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"denarius-web","inject":["DB_PASS"],"runtime":[]}]}"#,
    )
    .unwrap();
    let text = capture_logs(|| {
        let entries = vec![SealEntry {
            name: "APP_KEY".into(),
            kind: Kind::Env,
            bytes: b"k",
        }];
        let _ = validate_seal_entries(&catalog, "denarius-web", &entries);
    });
    assert!(
        text.contains("catalog refuse seal entry"),
        "logs: {text}"
    );
}

#[test]
fn log_catalog_refuse_serve_on_non_socket_profile() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"denarius-web","inject":["DB_PASS"],"runtime":[],"socket":false}]}"#,
    )
    .unwrap();
    let text = capture_logs(|| {
        let _ = validate_serve_entry(&catalog, "denarius-web", Kind::Env, "DB_PASS");
    });
    assert!(
        text.contains("catalog refuse serve on non-socket profile"),
        "logs: {text}"
    );
}

#[test]
fn log_catalog_refuse_serve_entry() {
    let catalog = parse_catalog_text(WORKER).unwrap();
    let text = capture_logs(|| {
        let _ = validate_serve_entry(&catalog, "denarius-worker", Kind::Env, "DB_PASS");
    });
    assert!(
        text.contains("catalog refuse serve entry"),
        "logs: {text}"
    );
}

const WORKER: &str = r#"{"profiles":[{
  "name":"denarius-worker",
  "inject":["DB_PASS"],
  "runtime":["APP_KEY"],
  "socket":true,
  "require_uid":1
}]}"#;
