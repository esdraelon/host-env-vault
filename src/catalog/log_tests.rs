use super::{parse_catalog_text, validate_seal_entries, validate_serve_entry, SealEntry};
use crate::legacy::profile::Kind;
use crate::testing::log_test_capture::capture_info_logs;
use serial_test::serial;

#[serial]
#[test]
fn log_catalog_parse_failure() {
    let text = capture_info_logs(|| {
        let _ = parse_catalog_text("{ not json");
    });
    assert!(text.contains("catalog parse failed"), "logs: {text}");
}

#[serial]
#[test]
fn log_catalog_refuse_seal_entry() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#,
    )
    .unwrap();
    let text = capture_info_logs(|| {
        let entries = vec![SealEntry {
            name: "APP_KEY".into(),
            kind: Kind::Env,
            bytes: b"k",
        }];
        let _ = validate_seal_entries(&catalog, "app-web", &entries);
    });
    assert!(text.contains("catalog refuse seal entry"), "logs: {text}");
}

#[serial]
#[test]
fn log_catalog_refuse_serve_on_non_socket_profile() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[],"socket":false}]}"#,
    )
    .unwrap();
    let text = capture_info_logs(|| {
        let _ = validate_serve_entry(&catalog, "app-web", Kind::Env, "DB_PASS");
    });
    assert!(
        text.contains("catalog refuse serve on non-socket profile"),
        "logs: {text}"
    );
}

#[serial]
#[test]
fn log_catalog_refuse_serve_entry() {
    let catalog = parse_catalog_text(WORKER).unwrap();
    let text = capture_info_logs(|| {
        let _ = validate_serve_entry(&catalog, "app-worker", Kind::Env, "DB_PASS");
    });
    assert!(text.contains("catalog refuse serve entry"), "logs: {text}");
}

const WORKER: &str = r#"{"profiles":[{
  "name":"app-worker",
  "inject":["DB_PASS"],
  "runtime":["APP_KEY"],
  "socket":true,
  "require_uid":1
}]}"#;
