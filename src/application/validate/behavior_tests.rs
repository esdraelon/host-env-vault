use std::path::{Path, PathBuf};

use crate::application::manifest::{default_manifests_dir, write_manifest_for_profile};
use crate::application::validate::{validate_from_local, validate_from_ssm, ValidateOptions};
use crate::catalog::{parse_catalog_text, DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};
use crate::config::SyncSourceKind;
use crate::core::error::Error;
use crate::application::validate::validate_from_secret_source;
use crate::ports::secret_source::{
    LocalSecretSource, SecretSource, SsmSecretSource, LOCAL_CATALOG_FILE,
};
use crate::ports::{MemoryS3, MemorySsm};

const WEB_CATALOG: &str = r#"{
  "profiles": [{
    "name": "app-web",
    "inject": ["DB_PASS"],
    "runtime": []
  }]
}"#;

const WEB_WITH_DOCUMENT: &str = r#"{
  "profiles": [{
    "name": "app-web",
    "inject": ["DB_PASS"],
    "runtime": [],
    "documents": ["nginx/site.conf"]
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

fn seed_manifests(state_dir: &Path, catalog_text: &str) {
    let catalog = parse_catalog_text(catalog_text).unwrap();
    let dir = default_manifests_dir(state_dir);
    for name in catalog.profile_names() {
        write_manifest_for_profile(&dir, catalog.profile(name).unwrap()).unwrap();
    }
}

fn ssm_options(state_dir: PathBuf) -> ValidateOptions {
    ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    )
    .with_manifest_lookup(state_dir, SyncSourceKind::Ssm, None, None)
}

fn local_options(secrets_dir: PathBuf) -> ValidateOptions {
    ValidateOptions::new(
        DEFAULT_CATALOG_PARAMETER.to_owned(),
        DEFAULT_SECRETS_PREFIX.to_owned(),
    )
    .with_manifest_lookup(
        secrets_dir.clone(),
        SyncSourceKind::Local,
        Some(secrets_dir),
        None,
    )
}

#[test]
fn validate_all_entries_present_succeeds_without_writing_state() {
    let state_dir = temp_root("ok-ssm");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    seed_manifests(&state_dir, WEB_CATALOG);
    let ssm = MemorySsm::new();
    seed_web_ssm(&ssm);
    validate_from_ssm(&ssm, &ssm_options(state_dir.clone())).unwrap();
    assert!(!state_dir.join("app-web.hev").exists());
    assert!(!state_dir.join("catalog.json").exists());
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn validate_missing_entry_fails_with_profile_count() {
    let state_dir = temp_root("missing-entry");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    seed_manifests(&state_dir, WEB_CATALOG);
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB_CATALOG);
    assert!(matches!(
        validate_from_ssm(&ssm, &ssm_options(state_dir.clone())),
        Err(Error::ValidateFailed { count: 1 })
    ));
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn validate_missing_manifest_fails() {
    let state_dir = temp_root("no-manifest");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    let ssm = MemorySsm::new();
    seed_web_ssm(&ssm);
    assert!(matches!(
        validate_from_ssm(&ssm, &ssm_options(state_dir.clone())),
        Err(Error::ValidateFailed { count: 1 })
    ));
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn validate_single_profile_flag_skips_other_profiles() {
    let state_dir = temp_root("one-profile");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    seed_manifests(&state_dir, WEB_CATALOG);
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, TWO_PROFILE_CATALOG);
    ssm.put("/host-env-vault/app-web/DB_PASS", "web-db");
    let options = ssm_options(state_dir.clone()).with_profile("app-web");
    validate_from_ssm(&ssm, &options).unwrap();
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn validate_local_source_reads_catalog_without_snapshot_write() {
    let root = temp_root("local");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join(LOCAL_CATALOG_FILE), WEB_CATALOG).unwrap();
    std::fs::write(root.join("app-web.env"), "DB_PASS=local-secret\n").unwrap();
    let catalog = parse_catalog_text(WEB_CATALOG).unwrap();
    write_manifest_for_profile(&root, catalog.profile("app-web").unwrap()).unwrap();
    validate_from_local(&root, None, &local_options(root.clone())).unwrap();
    let source = LocalSecretSource::new(&root);
    assert_eq!(source.load_catalog().unwrap(), WEB_CATALOG);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn validate_unknown_profile_filter_errors() {
    let state_dir = temp_root("unknown-profile");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    seed_manifests(&state_dir, WEB_CATALOG);
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB_CATALOG);
    ssm.put("/host-env-vault/app-web/DB_PASS", "ok");
    let options = ssm_options(state_dir.clone()).with_profile("missing-profile");
    assert!(matches!(
        validate_from_ssm(&ssm, &options),
        Err(Error::NotInCatalog(name)) if name == "missing-profile"
    ));
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn validate_manifest_mismatch_extra_catalog_key_fails() {
    let root = temp_root("manifest-mismatch");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join(LOCAL_CATALOG_FILE), WEB_CATALOG).unwrap();
    std::fs::write(root.join("app-web.env"), "DB_PASS=ok\n").unwrap();
    std::fs::write(
        root.join("app-web.env-host-vault"),
        r#"profile = "app-web"
[inject]
env = []
files = []
[runtime]
env = []
files = []
"#,
    )
    .unwrap();
    assert!(matches!(
        validate_from_local(&root, None, &local_options(root.clone())),
        Err(Error::ValidateFailed { count: 1 })
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn validate_counts_s3_documents_in_entry_total() {
    let state_dir = temp_root("s3-docs");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    seed_manifests(&state_dir, WEB_WITH_DOCUMENT);
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB_WITH_DOCUMENT);
    ssm.put("/host-env-vault/app-web/DB_PASS", "db-secret-value");
    let s3 = MemoryS3::new();
    s3.put("recovery/nginx/site.conf", b"server { listen 443; }");
    let secrets = SsmSecretSource::new(
        DEFAULT_CATALOG_PARAMETER,
        DEFAULT_SECRETS_PREFIX,
        &ssm,
    );
    let options = ssm_options(state_dir.clone()).with_s3_prefix("recovery");
    let text = crate::testing::log_test_capture::capture_info_logs(|| {
        validate_from_secret_source(&secrets, Some(&s3), &options).unwrap();
    });
    assert!(
        text.contains("entries=2"),
        "expected inject + document count in logs: {text}"
    );
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn validate_manifest_override_requires_profile_flag() {
    let root = temp_root("override-no-profile");
    let _ = std::fs::remove_dir_all(&root);
    let ssm = MemorySsm::new();
    seed_web_ssm(&ssm);
    seed_manifests(&root, WEB_CATALOG);
    let options = ssm_options(root.clone())
        .with_manifest_override(root.join("unused.env-host-vault"));
    assert!(matches!(
        validate_from_ssm(&ssm, &options),
        Err(Error::CatalogParse(_))
    ));
    let _ = std::fs::remove_dir_all(&root);
}
