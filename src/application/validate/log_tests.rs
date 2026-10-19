use serial_test::serial;

use crate::application::validate::{validate_from_ssm, ValidateOptions};
use crate::catalog::{DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};
use crate::core::error::Error;
use crate::ports::MemorySsm;
use crate::testing::log_test_capture::capture_info_logs;

const WEB: &str = r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#;

#[serial]
#[test]
fn log_validate_catalog_loaded_and_profile_ok() {
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB);
    ssm.put("/host-env-vault/app-web/DB_PASS", "secret");
    let state_dir = std::env::temp_dir().join(format!(
        "hev-validate-log-ok-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    crate::application::manifest::write_manifest_for_profile(
        &crate::application::manifest::default_manifests_dir(&state_dir),
        crate::catalog::parse_catalog_text(WEB).unwrap().profile("app-web").unwrap(),
    )
    .unwrap();
    let options = ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    )
    .with_manifest_lookup(
        state_dir.clone(),
        crate::config::SyncSourceKind::Ssm,
        None,
        None,
    );
    let text = capture_info_logs(|| {
        validate_from_ssm(&ssm, &options).unwrap();
    });
    assert!(text.contains("validate catalog loaded"), "logs: {text}");
    assert!(text.contains("validate profile ok"), "logs: {text}");
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[serial]
#[test]
fn log_validate_profile_failed() {
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB);
    let state_dir = std::env::temp_dir().join(format!(
        "hev-validate-log-fail-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    crate::application::manifest::write_manifest_for_profile(
        &crate::application::manifest::default_manifests_dir(&state_dir),
        crate::catalog::parse_catalog_text(WEB).unwrap().profile("app-web").unwrap(),
    )
    .unwrap();
    let options = ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    )
    .with_manifest_lookup(
        state_dir.clone(),
        crate::config::SyncSourceKind::Ssm,
        None,
        None,
    );
    let text = capture_info_logs(|| {
        assert!(matches!(
            validate_from_ssm(&ssm, &options),
            Err(Error::ValidateFailed { count: 1 })
        ));
    });
    assert!(text.contains("validate profile failed"), "logs: {text}");
    let _ = std::fs::remove_dir_all(&state_dir);
}
