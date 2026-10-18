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
    let options = ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    );
    let text = capture_info_logs(|| {
        validate_from_ssm(&ssm, &options).unwrap();
    });
    assert!(text.contains("validate catalog loaded"), "logs: {text}");
    assert!(text.contains("validate profile ok"), "logs: {text}");
}

#[serial]
#[test]
fn log_validate_profile_failed() {
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB);
    let options = ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    );
    let text = capture_info_logs(|| {
        assert!(matches!(
            validate_from_ssm(&ssm, &options),
            Err(Error::ValidateFailed { count: 1 })
        ));
    });
    assert!(text.contains("validate profile failed"), "logs: {text}");
}
