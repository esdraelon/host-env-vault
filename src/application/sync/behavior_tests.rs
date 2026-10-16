use std::path::PathBuf;

use crate::application::sync::{
    bundle_path, sync_from_ports, sync_from_ssm, SyncOptions, SYNC_SLOT_INDEX,
};
use crate::application::sync::{load_or_create_identity, sync_catalog_from_text};
use crate::catalog::parse_catalog_text;
use crate::catalog::{DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};
use crate::core::error::Error;
use crate::core::slot::{SlotTable, SECRET_MAX_BYTES};
use crate::legacy::profile::Kind;
use crate::ports::{MemoryS3, MemorySsm, SsmError, SsmPort, SsmSecretSource};
use crate::vault::bundle::{open_bytes, seal_bytes, Entry};
use crate::vault::kek::AgeKek;
use zeroize::Zeroizing;

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
    {"name": "edge-proxy", "inject": ["STRIPE_SECRET_KEY"], "runtime": []}
  ]
}"#;

fn temp_state_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("hev-sync-{label}-{}-{id}", std::process::id()))
}

fn seed_web_ssm(ssm: &MemorySsm) {
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB_CATALOG);
    ssm.put("/host-env-vault/app-web/DB_PASS", "db-secret-value");
}

fn seed_two_profile_ssm(ssm: &MemorySsm) {
    ssm.put(DEFAULT_CATALOG_PARAMETER, TWO_PROFILE_CATALOG);
    ssm.put("/host-env-vault/app-web/DB_PASS", "web-db");
    ssm.put("/host-env-vault/edge-proxy/STRIPE_SECRET_KEY", "sk_live");
}

#[test]
fn sync_writes_bundle_with_empty_state_dir_parent() {
    let work = temp_state_dir("flat-bundle");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let previous = std::env::current_dir().unwrap();
    std::env::set_current_dir(&work).unwrap();
    let ssm = MemorySsm::new();
    seed_web_ssm(&ssm);
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: work.join("kek.age"),
        state_dir: PathBuf::from("."),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        s3_prefix: None,
    };
    sync_from_ssm(&ssm, &kek, &mut table, &options).unwrap();
    assert!(work.join("app-web.hev").is_file());
    std::env::set_current_dir(previous).unwrap();
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn sync_success_replaces_bundle_on_disk() {
    let state_dir = temp_state_dir("success");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    seed_web_ssm(&ssm);
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: state_dir.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        s3_prefix: None,
    };
    sync_from_ssm(&ssm, &kek, &mut table, &options).unwrap();
    let path = bundle_path(&state_dir, "app-web");
    let bytes = std::fs::read(&path).unwrap();
    let opened = open_bytes(&bytes, &kek).unwrap();
    assert_eq!(opened.profile, "app-web");
    assert_eq!(opened.entries.len(), 1);
    assert_eq!(opened.entries[0].name, "DB_PASS");
    assert_eq!(&*opened.entries[0].bytes, b"db-secret-value");
    assert!(!table.slot_ref(SYNC_SLOT_INDEX).unwrap().in_use());
    assert!(table
        .slot_ref(SYNC_SLOT_INDEX)
        .unwrap()
        .profile_name_bytes()
        .is_empty());
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn sync_failed_pull_keeps_previous_bundle_bytes() {
    let state_dir = temp_state_dir("keep-old");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    let kek = AgeKek::generate();
    let stale = seal_bytes(
        "app-web",
        vec![Entry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: Zeroizing::new(b"stale-secret".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    let bundle_file = bundle_path(&state_dir, "app-web");
    std::fs::write(&bundle_file, &stale).unwrap();

    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB_CATALOG);
    // DB_PASS parameter intentionally missing

    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: state_dir.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        s3_prefix: None,
    };
    assert!(matches!(
        sync_from_ssm(&ssm, &kek, &mut table, &options),
        Err(Error::SyncFailed { count: 1 })
    ));
    let after = std::fs::read(&bundle_file).unwrap();
    assert_eq!(after, stale);
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn pull_from_ssm_does_not_occupy_sync_slot() {
    let ssm = MemorySsm::new();
    seed_web_ssm(&ssm);
    let catalog = parse_catalog_text(WEB_CATALOG).unwrap();
    let definition = catalog.profile("app-web").unwrap();
    let table = SlotTable::new();
    let secrets = SsmSecretSource::new(
        DEFAULT_CATALOG_PARAMETER,
        DEFAULT_SECRETS_PREFIX,
        &ssm,
    );
    super::pull_profile_entries(&secrets, definition).unwrap();
    assert!(!table.slot_ref(SYNC_SLOT_INDEX).unwrap().in_use());
    assert!(table
        .slot_ref(SYNC_SLOT_INDEX)
        .unwrap()
        .profile_name_bytes()
        .is_empty());
}

#[test]
fn sync_two_profiles_leaves_slot_free_between_and_after() {
    let state_dir = temp_state_dir("two-profiles");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    seed_two_profile_ssm(&ssm);
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: state_dir.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        s3_prefix: None,
    };
    sync_from_ssm(&ssm, &kek, &mut table, &options).unwrap();
    assert!(!table.slot_ref(SYNC_SLOT_INDEX).unwrap().in_use());
    assert!(table
        .slot_ref(SYNC_SLOT_INDEX)
        .unwrap()
        .profile_name_bytes()
        .is_empty());
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn load_or_create_identity_mints_then_reloads() {
    let state_dir = temp_state_dir("identity");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    let path = state_dir.join("kek.age");
    let minted = load_or_create_identity(&path).unwrap();
    assert!(path.is_file());
    let loaded = load_or_create_identity(&path).unwrap();
    let dek = [4u8; 32];
    let wrapped = minted.wrap_dek(&dek).unwrap();
    assert_eq!(&*loaded.unwrap_dek(&wrapped).unwrap(), &dek);
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn missing_catalog_parameter_fails_without_writing_bundles() {
    let state_dir = temp_state_dir("no-catalog");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    let ssm = MemorySsm::new();
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: state_dir.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        s3_prefix: None,
    };
    assert!(matches!(
        sync_from_ssm(&ssm, &kek, &mut table, &options),
        Err(Error::SsmMissing(_))
    ));
    assert!(!bundle_path(&state_dir, "app-web").exists());
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn unavailable_catalog_ssm_maps_to_parse_error() {
    struct UnavailableCatalog(MemorySsm);

    impl SsmPort for UnavailableCatalog {
        fn get_parameter(&self, name: &str) -> Result<String, SsmError> {
            if name == DEFAULT_CATALOG_PARAMETER {
                return Err(SsmError::Unavailable);
            }
            self.0.get_parameter(name)
        }
    }

    let state_dir = temp_state_dir("ssm-down");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = UnavailableCatalog(MemorySsm::new());
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: state_dir.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        s3_prefix: None,
    };
    assert!(matches!(
        sync_from_ssm(&ssm, &kek, &mut table, &options),
        Err(Error::CatalogParse(_))
    ));
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn sync_catalog_from_text_matches_ssm_catalog_path() {
    let state_dir = temp_state_dir("from-text");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    ssm.put("/host-env-vault/app-web/DB_PASS", "from-text");
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    sync_catalog_from_text(WEB_CATALOG, DEFAULT_SECRETS_PREFIX, &ssm, None, None, &kek, &mut table, &state_dir).unwrap();
    let bytes = std::fs::read(bundle_path(&state_dir, "app-web")).unwrap();
    let opened = open_bytes(&bytes, &kek).unwrap();
    assert_eq!(&*opened.entries[0].bytes, b"from-text");
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn max_length_ssm_value_is_accepted() {
    let state_dir = temp_state_dir("max-len");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB_CATALOG);
    let value = "x".repeat(SECRET_MAX_BYTES);
    ssm.put("/host-env-vault/app-web/DB_PASS", value.clone());
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: state_dir.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        s3_prefix: None,
    };
    sync_from_ssm(&ssm, &kek, &mut table, &options).unwrap();
    let opened = open_bytes(
        &std::fs::read(bundle_path(&state_dir, "app-web")).unwrap(),
        &kek,
    )
    .unwrap();
    assert_eq!(opened.entries[0].bytes.len(), SECRET_MAX_BYTES);
    let _ = std::fs::remove_dir_all(&state_dir);
}

const FILE_CATALOG: &str = r#"{
  "profiles": [{
    "name": "app-worker",
    "inject": [],
    "runtime": [],
    "runtime_files": ["teller.key"]
  }]
}"#;

#[test]
fn file_entries_skip_env_line_validation() {
    let state_dir = temp_state_dir("file-entry");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, FILE_CATALOG);
    ssm.put("/host-env-vault/app-worker/teller.key", "line-one\nline-two");
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: state_dir.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        s3_prefix: None,
    };
    sync_from_ssm(&ssm, &kek, &mut table, &options).unwrap();
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn sync_catalog_from_text_counts_profile_failures() {
    let state_dir = temp_state_dir("text-partial");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    ssm.put("/host-env-vault/app-web/DB_PASS", "ok");
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    assert!(matches!(
        sync_catalog_from_text(
            TWO_PROFILE_CATALOG,
            DEFAULT_SECRETS_PREFIX,
            &ssm,
            None,
            None,
            &kek,
            &mut table,
            &state_dir
        ),
        Err(Error::SyncFailed { count: 1 })
    ));
    assert!(bundle_path(&state_dir, "app-web").exists());
    assert!(!bundle_path(&state_dir, "edge-proxy").exists());
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn invalid_env_value_from_ssm_is_rejected() {
    let state_dir = temp_state_dir("bad-env");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WEB_CATALOG);
    ssm.put("/host-env-vault/app-web/DB_PASS", "bad\nline");
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: state_dir.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        s3_prefix: None,
    };
    assert!(matches!(
        sync_from_ssm(&ssm, &kek, &mut table, &options),
        Err(Error::SyncFailed { count: 1 })
    ));
    let _ = std::fs::remove_dir_all(&state_dir);
}

const NGINX_DOC_CATALOG: &str = r#"{
  "profiles": [{
    "name": "nginx",
    "inject": [],
    "runtime": [],
    "documents": ["nginx/site-a.conf"]
  }]
}"#;

#[test]
fn sync_seals_nginx_documents_from_fake_s3() {
    let state_dir = temp_state_dir("nginx-s3");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, NGINX_DOC_CATALOG);
    let s3 = MemoryS3::new();
    s3.put("recovery/nginx/site-a.conf", b"server { listen 443; }");
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: state_dir.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        s3_prefix: Some("recovery".into()),
    };
    sync_from_ports(&ssm, Some(&s3), &kek, &mut table, &options).unwrap();
    let path = bundle_path(&state_dir, "nginx");
    let bytes = std::fs::read(&path).unwrap();
    let opened = open_bytes(&bytes, &kek).unwrap();
    assert_eq!(opened.profile, "nginx");
    assert_eq!(opened.entries.len(), 1);
    assert_eq!(opened.entries[0].name, "site-a.conf");
    assert_eq!(&*opened.entries[0].bytes, b"server { listen 443; }");
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn atomic_replace_does_not_leave_tmp_when_rename_succeeds() {
    let state_dir = temp_state_dir("atomic");
    let _ = std::fs::remove_dir_all(&state_dir);
    let ssm = MemorySsm::new();
    seed_web_ssm(&ssm);
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: state_dir.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
        s3_prefix: None,
    };
    sync_from_ssm(&ssm, &kek, &mut table, &options).unwrap();
    assert!(!state_dir.join("app-web.hev.tmp").exists());
    let _ = std::fs::remove_dir_all(&state_dir);
}
