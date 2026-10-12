use super::{open_profile_into_slot, seal_profile_in_slot};
use crate::bundle::{seal_bytes, Entry};
use crate::catalog::parse_catalog_text;
use crate::catalog::SealEntry;
use crate::kek::AgeKek;
use crate::profile::Kind;
use crate::slot::SlotTable;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
use zeroize::Zeroizing;

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

const WEB: &str = r#"{"profiles":[{"name":"denarius-web","inject":["DB_PASS"],"runtime":[]}]}"#;

#[test]
fn log_local_bundle_seal_from_slot() {
    let catalog = parse_catalog_text(WEB).unwrap();
    let kek = AgeKek::generate();
    let text = capture_logs(|| {
        let mut table = SlotTable::new();
        let lease = table.try_acquire(0, Instant::now()).unwrap();
        let slot = table.slot_ref_mut(0).unwrap();
        let entries = vec![SealEntry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: b"x",
        }];
        let _ = seal_profile_in_slot(&catalog, slot, lease, "denarius-web", &entries, &kek);
    });
    assert!(
        text.contains("local bundle seal from slot"),
        "logs: {text}"
    );
}

#[test]
fn log_local_bundle_open_into_slot() {
    let catalog = parse_catalog_text(WEB).unwrap();
    let kek = AgeKek::generate();
    let bundle = seal_bytes(
        "denarius-web",
        vec![Entry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: Zeroizing::new(b"x".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    let text = capture_logs(|| {
        let mut table = SlotTable::new();
        let lease = table.try_acquire(0, Instant::now()).unwrap();
        let slot = table.slot_ref_mut(0).unwrap();
        let _ = open_profile_into_slot(&catalog, &bundle, slot, lease, &kek);
    });
    assert!(
        text.contains("local bundle open into slot"),
        "logs: {text}"
    );
}

#[test]
fn log_local_bundle_refuse_open_not_in_catalog() {
    let catalog = parse_catalog_text(WEB).unwrap();
    let kek = AgeKek::generate();
    let bundle = seal_bytes(
        "nginx",
        vec![Entry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: Zeroizing::new(b"x".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    let text = capture_logs(|| {
        let mut table = SlotTable::new();
        let lease = table.try_acquire(0, Instant::now()).unwrap();
        let slot = table.slot_ref_mut(0).unwrap();
        let _ = open_profile_into_slot(&catalog, &bundle, slot, lease, &kek);
    });
    assert!(
        text.contains("local bundle refuse open not in catalog"),
        "logs: {text}"
    );
}

#[test]
fn log_local_bundle_refuse_open_entry() {
    let catalog = parse_catalog_text(WEB).unwrap();
    let kek = AgeKek::generate();
    let bundle = seal_bytes(
        "denarius-web",
        vec![Entry {
            name: "APP_KEY".into(),
            kind: Kind::Env,
            bytes: Zeroizing::new(b"k".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    let text = capture_logs(|| {
        let mut table = SlotTable::new();
        let lease = table.try_acquire(0, Instant::now()).unwrap();
        let slot = table.slot_ref_mut(0).unwrap();
        let _ = open_profile_into_slot(&catalog, &bundle, slot, lease, &kek);
    });
    assert!(
        text.contains("local bundle refuse open entry"),
        "logs: {text}"
    );
}
