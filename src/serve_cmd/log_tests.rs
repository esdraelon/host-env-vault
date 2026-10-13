use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

use crate::catalog::{
    load_catalog_snapshot, parse_catalog_text, write_catalog_snapshot, DEFAULT_CATALOG_PARAMETER,
};
use crate::kek::AgeKek;
use crate::port::MemorySsm;
use crate::profile::Kind;
use crate::serve_cmd::{bind_serve_socket, fetch_runtime_entry, ServeOptions};
use crate::slot::SlotTable;
use crate::sync::{sync_from_ssm, SyncOptions};

const WORKER: &str = r#"{
  "profiles": [{
    "name": "denarius-worker",
    "inject": ["DB_PASS"],
    "runtime": ["APP_KEY"],
    "socket": true,
    "require_uid": 33
  }]
}"#;

fn capture_logs<F: FnOnce()>(test: F) -> Vec<String> {
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
    let captured = lines.lock().unwrap().clone();
    captured
}

struct LogWriter(Arc<Mutex<Vec<String>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().push(String::from_utf8_lossy(buf).to_string());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn joined(lines: &[String]) -> String {
    lines.concat()
}

fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "hev-serve-log-{label}-{}",
        std::process::id()
    ))
}

#[test]
fn log_serve_deny_runtime_entry_and_return_success() {
    let root = temp_dir("deny-ok");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let state_dir = root.join("state");
    fs::create_dir(&state_dir).unwrap();
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WORKER);
    ssm.put("/amtgard/denarius-worker/DB_PASS", "db");
    ssm.put("/amtgard/denarius-worker/APP_KEY", "key");
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    sync_from_ssm(
        &ssm,
        &kek,
        &mut table,
        &SyncOptions {
            identity_path: root.join("kek.age"),
            state_dir: state_dir.clone(),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            s3_prefix: None,
        },
    )
    .unwrap();
    let catalog = load_catalog_snapshot(&state_dir).unwrap();

    let deny_lines = capture_logs(|| {
        let mut t = SlotTable::new();
        let _ = fetch_runtime_entry(
            &kek,
            &mut t,
            &catalog,
            "denarius-worker",
            &state_dir,
            Kind::Env,
            "DB_PASS",
        );
    });
    let deny_text = joined(&deny_lines);
    assert!(
        deny_text.contains("catalog refuse serve entry"),
        "{deny_text}"
    );

    let ok_lines = capture_logs(|| {
        let mut t = SlotTable::new();
        let _ = fetch_runtime_entry(
            &kek,
            &mut t,
            &catalog,
            "denarius-worker",
            &state_dir,
            Kind::Env,
            "APP_KEY",
        );
    });
    let ok_text = joined(&ok_lines);
    assert!(
        ok_text.contains("serve returned runtime entry"),
        "{ok_text}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn log_serve_refuse_profile_without_socket() {
    let catalog_text =
        r#"{"profiles":[{"name":"denarius-web","inject":["DB_PASS"],"runtime":[],"socket":false}]}"#;
    let _catalog = parse_catalog_text(catalog_text).unwrap();
    let root = temp_dir("nosock");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    fs::create_dir_all(&root).unwrap();
    write_catalog_snapshot(&root, catalog_text).unwrap();
    let options = ServeOptions::new(
        root.join("kek.age"),
        root.clone(),
        root.join("run"),
        "denarius-web",
    );
    let lines = capture_logs(|| {
        let _ = bind_serve_socket(&options);
    });
    let text = joined(&lines);
    assert!(
        text.contains("serve refuse profile without socket"),
        "{text}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn log_serve_deny_peer_uid() {
    use std::os::unix::net::UnixStream;

    let root = temp_dir("uid-log");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let state_dir = root.join("state");
    fs::create_dir(&state_dir).unwrap();
    write_catalog_snapshot(&state_dir, WORKER).unwrap();
    let catalog = load_catalog_snapshot(&state_dir).unwrap();
    let kek = AgeKek::generate();
    let options = ServeOptions::new(
        root.join("kek.age"),
        state_dir,
        root.join("run"),
        "denarius-worker",
    );
    let mut table = SlotTable::new();
    let (mut server, client) = UnixStream::pair().unwrap();
    drop(client);

    let lines = capture_logs(|| {
        let _ = crate::serve_cmd::handle_serve_connection(
            &mut server,
            &kek,
            &mut table,
            &catalog,
            &options,
        );
    });
    assert!(joined(&lines).contains("serve deny peer uid"));
    fs::remove_dir_all(root).unwrap();
}
