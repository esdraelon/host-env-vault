use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::application::manifest::{default_manifests_dir, write_manifest_for_profile};
use crate::application::sync::{sync_from_host_store, SyncOptions};
use crate::catalog::parse_catalog_text;
use crate::config::SyncSourceKind;
use crate::core::slot::SlotTable;
use crate::ports::{LocalSecretSource, LOCAL_CATALOG_FILE};
use crate::vault::host_store::{write_profile_store, write_profile_store_with_backend, StoreBackend};
use crate::vault::kek::AgeKek;

const CATALOG: &str = r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#;

const MIXED_CATALOG: &str = r#"{"profiles":[
    {"name":"app-web","inject":["DB_PASS"],"runtime":[]},
    {"name":"app-worker","inject":["WORKER_TOKEN"],"runtime":[]}
]}"#;

fn temp_root(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-m19-{label}-{}-{id}",
        std::process::id()
    ))
}

#[test]
fn host_store_sync_seals_bundle_from_encrypted_store() {
    let root = temp_root("sync");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let catalog_dir = root.join("catalog");
    fs::create_dir_all(&catalog_dir).unwrap();
    fs::write(catalog_dir.join(LOCAL_CATALOG_FILE), CATALOG).unwrap();
    let store_dir = root.join("store");
    let state_dir = root.join("state");
    let kek = AgeKek::generate();
    let mut entries = HashMap::new();
    entries.insert("DB_PASS".into(), "store-secret".into());
    write_profile_store(&store_dir, "app-web", &entries, &kek).unwrap();
    write_manifest_for_profile(
        &default_manifests_dir(&state_dir),
        parse_catalog_text(CATALOG).unwrap().profile("app-web").unwrap(),
    )
    .unwrap();
    let catalog = LocalSecretSource::new(&catalog_dir);
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: root.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: String::new(),
        secrets_prefix: String::new(),
        source: SyncSourceKind::HostStore,
        local_secrets_dir: Some(catalog_dir),
        manifests_dir: None,
        s3_prefix: None,
    };
    sync_from_host_store(&catalog, &store_dir, &kek, None, &mut table, &options).unwrap();
    assert!(state_dir.join("app-web.hev").is_file());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn host_store_sync_mixed_flat_and_sqlite_profiles() {
    let root = temp_root("mixed-backends");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let catalog_dir = root.join("catalog");
    fs::create_dir_all(&catalog_dir).unwrap();
    fs::write(catalog_dir.join(LOCAL_CATALOG_FILE), MIXED_CATALOG).unwrap();
    let store_dir = root.join("store");
    let state_dir = root.join("state");
    let kek = AgeKek::generate();
    let mut flat = HashMap::new();
    flat.insert("DB_PASS".into(), "flat-secret".into());
    write_profile_store(&store_dir, "app-web", &flat, &kek).unwrap();
    let mut sqlite = HashMap::new();
    sqlite.insert("WORKER_TOKEN".into(), "sqlite-secret".into());
    write_profile_store_with_backend(&store_dir, "app-worker", &sqlite, &kek, StoreBackend::Sqlite)
        .unwrap();
    let catalog = parse_catalog_text(MIXED_CATALOG).unwrap();
    for name in ["app-web", "app-worker"] {
        write_manifest_for_profile(
            &default_manifests_dir(&state_dir),
            catalog.profile(name).unwrap(),
        )
        .unwrap();
    }
    let catalog_source = LocalSecretSource::new(&catalog_dir);
    let mut table = SlotTable::new();
    let options = SyncOptions {
        identity_path: root.join("kek.age"),
        state_dir: state_dir.clone(),
        catalog_param: String::new(),
        secrets_prefix: String::new(),
        source: SyncSourceKind::HostStore,
        local_secrets_dir: Some(catalog_dir),
        manifests_dir: None,
        s3_prefix: None,
    };
    sync_from_host_store(&catalog_source, &store_dir, &kek, None, &mut table, &options).unwrap();
    assert!(state_dir.join("app-web.hev").is_file());
    assert!(state_dir.join("app-worker.hev").is_file());
    let _ = fs::remove_dir_all(&root);
}
