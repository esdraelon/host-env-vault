//! Serializes tracing capture across parallel integration tests.

use std::sync::{Arc, Mutex};

use tracing::dispatcher::{with_default, Dispatch};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

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

pub fn capture_info_logs<F: FnOnce()>(test: F) -> String {
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = lines.clone();
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .without_time()
        .with_target(true)
        .with_writer(move || LogWriter(sink.clone()))
        .with_filter(tracing_subscriber::filter::LevelFilter::INFO);
    let subscriber = tracing_subscriber::registry().with(layer);
    let dispatch = Dispatch::new(subscriber);
    with_default(&dispatch, test);
    let captured = lines.lock().unwrap().concat();
    captured
}
