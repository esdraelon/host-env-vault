use crate::application::documents::pull_profile_documents;
use crate::catalog::parse_catalog_text;
use crate::core::slot::DOCUMENT_MAX_BYTES;
use crate::ports::MemoryS3;
use crate::testing::log_test_capture::capture_info_logs;
use serial_test::serial;

#[serial]
#[test]
fn log_reject_oversize_s3_object() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["big.conf"]}]}"#,
    )
    .unwrap();
    let nginx = catalog.profile("nginx").unwrap();
    let s3 = MemoryS3::new();
    s3.put("big.conf", &vec![b'x'; DOCUMENT_MAX_BYTES + 1]);
    let joined = capture_info_logs(|| {
        let _ = pull_profile_documents(&s3, "", nginx);
    });
    assert!(joined.contains("documents reject oversize s3 object"));
}

#[serial]
#[test]
fn log_reject_secret_shaped_s3_key() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["oauth-private.key"]}]}"#,
    )
    .unwrap();
    let nginx = catalog.profile("nginx").unwrap();
    let s3 = MemoryS3::new();
    let joined = capture_info_logs(|| {
        let _ = pull_profile_documents(&s3, "", nginx);
    });
    assert!(joined.contains("documents reject secret-shaped s3 key"));
}

#[serial]
#[test]
fn log_loaded_s3_object() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["denarius.env"]}]}"#,
    )
    .unwrap();
    let nginx = catalog.profile("nginx").unwrap();
    let s3 = MemoryS3::new();
    s3.put("denarius.env", b"APP_ENV=prod\n");
    let joined = capture_info_logs(|| {
        pull_profile_documents(&s3, "", nginx).unwrap();
    });
    assert!(joined.contains("documents loaded s3 object"));
}
