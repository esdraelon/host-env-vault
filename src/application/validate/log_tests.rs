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

#[serial]
#[test]
fn log_validate_host_store_transition_mode() {
    use std::collections::HashMap;

    use crate::application::validate::validate_from_host_store;
    use crate::config::SyncSourceKind;
    use crate::ports::LocalSecretSource;
    use crate::vault::host_store::write_profile_store;
    use crate::vault::kek::AgeKek;

    let state_dir = std::env::temp_dir().join(format!(
        "hev-validate-host-store-log-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    crate::application::manifest::write_manifest_for_profile(
        &crate::application::manifest::default_manifests_dir(&state_dir),
        crate::catalog::parse_catalog_text(WEB).unwrap().profile("app-web").unwrap(),
    )
    .unwrap();
    let catalog_dir = state_dir.join("catalog");
    std::fs::create_dir_all(&catalog_dir).unwrap();
    std::fs::write(
        catalog_dir.join(crate::ports::LOCAL_CATALOG_FILE),
        WEB,
    )
    .unwrap();
    let store_dir = state_dir.join("store");
    let kek = AgeKek::generate();
    let mut entries = HashMap::new();
    entries.insert("DB_PASS".into(), "secret".into());
    write_profile_store(&store_dir, "app-web", &entries, &kek).unwrap();
    let catalog = LocalSecretSource::new(&catalog_dir);
    let options = ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    )
    .with_manifest_lookup(
        state_dir.clone(),
        SyncSourceKind::HostStore,
        Some(catalog_dir),
        None,
    );
    let text = capture_info_logs(|| {
        validate_from_host_store(&catalog, &store_dir, &kek, None, &options).unwrap();
    });
    assert!(
        text.contains("validate transition mode: host encrypted store active"),
        "logs: {text}"
    );
    assert!(text.contains("validate profile ok"), "logs: {text}");
    let _ = std::fs::remove_dir_all(&state_dir);
}
