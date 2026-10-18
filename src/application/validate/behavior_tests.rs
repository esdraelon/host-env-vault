use std::path::PathBuf;

use crate::application::validate::{validate_from_local, validate_from_ssm, ValidateOptions};
use crate::catalog::{DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};
use crate::core::error::Error;
use crate::ports::secret_source::{LocalSecretSource, SecretSource, LOCAL_CATALOG_FILE};
use crate::ports::MemorySsm;

const WEB_CATALOG: &str = r#"{
  "profiles": [{
    "name": "app-web",
    "inject": ["DB_PASS"],
    "runtime": []
  }]
}"#;

const TWO_PROFILE_CATALOG: &str = r#"{
  "profiles": [
    {"name": "app-web", "inject": ["DB_PASS"], "runtime": []},
    {"name": "edge-proxy", "inject": ["API_SECRET"], "runtime": []}
  ]
}"#;

fn temp_root(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("hev-validate-{label}-{}-{id}", std::process::id()))
}

fn seed_web_ssm(ssm: &MemorySsm) {
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB_CATALOG);
    ssm.put("/host-env-vault/app-web/DB_PASS", "db-secret-value");
}

#[test]
fn validate_all_entries_present_succeeds_without_writing_state() {
    let state_dir = temp_root("ok-ssm");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    let ssm = MemorySsm::new();
    seed_web_ssm(&ssm);
    let options = ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    );
    validate_from_ssm(&ssm, &options).unwrap();
    assert!(!state_dir.join("app-web.hev").exists());
    assert!(!state_dir.join("catalog.json").exists());
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn validate_missing_entry_fails_with_profile_count() {
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB_CATALOG);
    let options = ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    );
    assert!(matches!(
        validate_from_ssm(&ssm, &options),
        Err(Error::ValidateFailed { count: 1 })
    ));
}

#[test]
fn validate_single_profile_flag_skips_other_profiles() {
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, TWO_PROFILE_CATALOG);
    ssm.put("/host-env-vault/app-web/DB_PASS", "web-db");
    let options = ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    )
    .with_profile("app-web");
    validate_from_ssm(&ssm, &options).unwrap();
}

#[test]
fn validate_local_source_reads_catalog_without_snapshot_write() {
    let root = temp_root("local");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join(LOCAL_CATALOG_FILE), WEB_CATALOG).unwrap();
    std::fs::write(root.join("app-web.env"), "DB_PASS=local-secret\n").unwrap();
    let options = ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    );
    validate_from_local(&root, None, &options).unwrap();
    let source = LocalSecretSource::new(&root);
    assert_eq!(source.load_catalog().unwrap(), WEB_CATALOG);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn validate_unknown_profile_filter_errors() {
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB_CATALOG);
    ssm.put("/host-env-vault/app-web/DB_PASS", "ok");
    let options = ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    )
    .with_profile("missing-profile");
    assert!(matches!(
        validate_from_ssm(&ssm, &options),
        Err(Error::NotInCatalog(name)) if name == "missing-profile"
    ));
}

#[test]
fn validate_manifest_rejects_names_not_in_catalog() {
    let root = temp_root("manifest");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join(LOCAL_CATALOG_FILE), WEB_CATALOG).unwrap();
    std::fs::write(root.join("app-web.env"), "DB_PASS=ok\n").unwrap();
    let manifest = root.join(".host-env-vault.toml");
    std::fs::write(
        &manifest,
        r#"
profile = "app-web"
[inject]
env = ["NOT_IN_CATALOG"]
[runtime]
env = []
files = []
"#,
    )
    .unwrap();
    let options = ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    )
    .with_manifest(manifest);
    assert!(matches!(
        validate_from_local(&root, None, &options),
        Err(Error::ValidateFailed { count: 1 })
    ));
    let _ = std::fs::remove_dir_all(&root);
}
