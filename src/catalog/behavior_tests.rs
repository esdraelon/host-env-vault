use super::{
    bind_catalog_profile, load_catalog_from_ssm, parse_catalog_text, validate_seal_entries,
    validate_serve_entry, SealEntry, DEFAULT_CATALOG_PARAMETER,
};
use crate::core::error::Error;
use crate::core::slot::SlotTable;
use crate::legacy::profile::Kind;
use crate::ports::ssm::{MemorySsm, SsmError, SsmPort};
use std::time::Instant;

const WORKER_CATALOG: &str = r#"{
  "profiles": [{
    "name": "denarius-worker",
    "inject": ["DB_PASS", "STRIPE_WEBHOOK_SECRET"],
    "runtime": ["APP_KEY", "STRIPE_SECRET_KEY"],
    "runtime_files": ["teller.key"],
    "socket": true,
    "require_uid": 33
  }]
}"#;

#[test]
fn entry_outside_catalog_is_refused_on_seal() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let entries = vec![SealEntry {
        name: "STRIPE_PUBLISHABLE_KEY".into(),
        kind: Kind::Env,
        bytes: b"pk_test",
    }];
    let err = validate_seal_entries(&catalog, "denarius-worker", &entries).unwrap_err();
    assert!(matches!(err, Error::EntryNotAllowed { .. }));
}

#[test]
fn unknown_profile_is_refused_on_seal() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let entries = vec![SealEntry {
        name: "DB_PASS".into(),
        kind: Kind::Env,
        bytes: b"x",
    }];
    assert!(matches!(
        validate_seal_entries(&catalog, "nginx", &entries),
        Err(Error::NotInCatalog(_))
    ));
}

#[test]
fn entry_outside_runtime_list_is_refused_on_serve() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    assert!(validate_serve_entry(&catalog, "denarius-worker", Kind::Env, "DB_PASS").is_err());
    assert!(validate_serve_entry(&catalog, "denarius-worker", Kind::Env, "APP_KEY").is_ok());
}

#[test]
fn catalog_driven_slot_bind_does_not_use_profile_id_enum() {
    let ssm = MemorySsm::new();
    ssm.put(DEFAULT_CATALOG_PARAMETER, WORKER_CATALOG);
    let catalog = load_catalog_from_ssm(&ssm, DEFAULT_CATALOG_PARAMETER).unwrap();
    let mut table = SlotTable::new();
    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    bind_catalog_profile(&catalog, "denarius-worker", slot, lease).unwrap();
    assert_eq!(slot.profile_name_bytes(), b"denarius-worker");
}

#[test]
fn seal_rejects_invalid_name_and_env_value() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let bad_name = vec![SealEntry {
        name: "../x".into(),
        kind: Kind::Env,
        bytes: b"v",
    }];
    assert!(matches!(
        validate_seal_entries(&catalog, "denarius-worker", &bad_name),
        Err(Error::InvalidName(_))
    ));
    let bad_value = vec![SealEntry {
        name: "DB_PASS".into(),
        kind: Kind::Env,
        bytes: b"#bad",
    }];
    assert!(matches!(
        validate_seal_entries(&catalog, "denarius-worker", &bad_value),
        Err(Error::InvalidEnvValue(_))
    ));
    assert!(matches!(
        validate_seal_entries(&catalog, "denarius-worker", &[]),
        Err(Error::EmptyBundle)
    ));
}

#[test]
fn serve_rejects_non_socket_profile() {
    let text = r#"{"profiles":[{"name":"denarius-web","inject":["DB_PASS"],"runtime":[],"socket":false}]}"#;
    let catalog = parse_catalog_text(text).unwrap();
    assert!(matches!(
        validate_serve_entry(&catalog, "denarius-web", Kind::Env, "DB_PASS"),
        Err(Error::EntryNotAllowed { .. })
    ));
}

#[test]
fn missing_ssm_parameter_maps_to_error() {
    let ssm = MemorySsm::new();
    assert!(matches!(
        load_catalog_from_ssm(&ssm, DEFAULT_CATALOG_PARAMETER),
        Err(Error::SsmMissing(_))
    ));
}

struct BrokenSsm;

impl SsmPort for BrokenSsm {
    fn get_parameter(&self, _name: &str) -> Result<String, SsmError> {
        Err(SsmError::Unavailable)
    }
}

#[test]
fn unavailable_ssm_maps_to_catalog_parse_error() {
    assert!(matches!(
        load_catalog_from_ssm(&BrokenSsm, "/x"),
        Err(Error::CatalogParse(_))
    ));
}

#[test]
fn bind_unknown_profile_errors() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let mut table = SlotTable::new();
    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    assert!(matches!(
        bind_catalog_profile(&catalog, "missing", slot, lease),
        Err(Error::NotInCatalog(_))
    ));
}

#[test]
fn allowed_seal_entries_pass_for_inject_and_runtime() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let entries = vec![
        SealEntry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: b"db-secret",
        },
        SealEntry {
            name: "APP_KEY".into(),
            kind: Kind::Env,
            bytes: b"app-key",
        },
    ];
    assert!(validate_seal_entries(&catalog, "denarius-worker", &entries).is_ok());
}

#[test]
fn inject_only_entry_seals_without_being_on_runtime_list() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let worker = catalog.profile("denarius-worker").unwrap();
    assert!(worker.allows_seal(Kind::Env, "DB_PASS"));
    assert!(!worker.allows_serve(Kind::Env, "DB_PASS"));
    let entries = vec![SealEntry {
        name: "DB_PASS".into(),
        kind: Kind::Env,
        bytes: b"only-inject",
    }];
    assert!(validate_seal_entries(&catalog, "denarius-worker", &entries).is_ok());
}

#[test]
fn runtime_file_seals_without_inject_files() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let worker = catalog.profile("denarius-worker").unwrap();
    assert!(worker.inject_files().is_empty());
    assert_eq!(worker.runtime_files(), &["teller.key"]);
    assert!(worker.allows_seal(Kind::File, "teller.key"));
    let entries = vec![SealEntry {
        name: "teller.key".into(),
        kind: Kind::File,
        bytes: b"pem-bytes",
    }];
    assert!(validate_seal_entries(&catalog, "denarius-worker", &entries).is_ok());
}

#[test]
fn catalog_lists_env_and_file_slices_from_parse() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let names: Vec<_> = catalog.profile_names().collect();
    assert_eq!(names, vec!["denarius-worker"]);
    let worker = catalog.profile("denarius-worker").unwrap();
    assert_eq!(worker.inject_env(), &["DB_PASS", "STRIPE_WEBHOOK_SECRET"]);
    assert_eq!(worker.runtime_env(), &["APP_KEY", "STRIPE_SECRET_KEY"]);
    assert!(worker.inject_files().is_empty());
    assert_eq!(worker.runtime_files(), &["teller.key"]);

    let with_inject_files = parse_catalog_text(
        r#"{"profiles":[{"name":"p","inject":[],"runtime":[],"inject_files":["a.pem"],"runtime_files":[]}]}"#,
    )
    .unwrap();
    assert_eq!(
        with_inject_files.profile("p").unwrap().inject_files(),
        &["a.pem"]
    );
}
