use std::collections::HashMap;
use std::fs;

use super::flat::read_flat_profile_store;
use super::sqlite::read_sqlite_profile_store;
use super::{
    ensure_store_dir, list_stored_profiles, resolve_store_backend, sqlite_store_path,
    write_profile_store_with_backend, StoreBackend, *,
};
use crate::vault::kek::AgeKek;

fn temp_store_root(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-host-store-{label}-{}-{id}",
        std::process::id()
    ))
}

#[test]
fn profile_store_round_trip_sealed_on_disk() {
    let root = temp_store_root("round-trip");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let kek = AgeKek::generate();
    let mut entries = HashMap::new();
    entries.insert("DB_PASS".into(), "secret-value".into());
    write_profile_store(&root, "app-web", &entries, &kek).unwrap();
    let path = profile_store_path(&root, "app-web");
    assert!(path.is_file());
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let raw = fs::read(&path).unwrap();
    assert!(!raw.is_empty());
    assert!(!String::from_utf8_lossy(&raw).contains("secret-value"));
    let back = read_profile_store(&root, "app-web", &kek).unwrap();
    assert_eq!(back, entries);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn read_profile_store_maps_missing_file() {
    let root = temp_store_root("missing");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let kek = AgeKek::generate();
    assert!(matches!(
        read_profile_store(&root, "app-web", &kek),
        Err(crate::core::error::Error::SsmMissing(path)) if path.contains("app-web.secrets.age")
    ));
    assert!(matches!(
        read_flat_profile_store(&root, "app-web", &kek),
        Err(crate::core::error::Error::SsmMissing(path)) if path.contains("app-web.secrets.age")
    ));
    assert!(matches!(
        read_sqlite_profile_store(&root, "app-web", &kek),
        Err(crate::core::error::Error::SsmMissing(path)) if path.contains("app-web.secrets.db")
    ));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn list_stored_profiles_scans_secrets_age_files() {
    let root = temp_store_root("list");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let kek = AgeKek::generate();
    let mut entries = HashMap::new();
    entries.insert("K".into(), "v".into());
    write_profile_store(&root, "app-worker", &entries, &kek).unwrap();
    fs::write(root.join("notes.txt"), "skip").unwrap();
    let names = list_stored_profiles(&root).unwrap();
    assert_eq!(names, vec!["app-worker".to_string()]);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn ensure_store_dir_sets_restrictive_mode() {
    let root = temp_store_root("ensure");
    let _ = fs::remove_dir_all(&root);
    ensure_store_dir(&root).unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn read_profile_store_rejects_wrong_kek() {
    let root = temp_store_root("wrong-kek");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let kek = AgeKek::generate();
    let mut entries = HashMap::new();
    entries.insert("K".into(), "v".into());
    write_profile_store(&root, "app-web", &entries, &kek).unwrap();
    let other = AgeKek::generate();
    assert!(matches!(
        read_profile_store(&root, "app-web", &other),
        Err(crate::core::error::Error::Kek)
    ));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn sqlite_profile_store_round_trip_sealed_on_disk() {
    let root = temp_store_root("sqlite-round-trip");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let kek = AgeKek::generate();
    let mut entries = HashMap::new();
    entries.insert("DB_PASS".into(), "secret-value".into());
    write_profile_store_with_backend(&root, "app-worker", &entries, &kek, StoreBackend::Sqlite)
        .unwrap();
    let path = sqlite_store_path(&root, "app-worker");
    assert!(path.is_file());
    let raw = fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("secret-value"));
    assert_eq!(
        resolve_store_backend(&root, "app-worker").unwrap(),
        StoreBackend::Sqlite
    );
    let back = read_profile_store(&root, "app-worker", &kek).unwrap();
    assert_eq!(back, entries);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn list_stored_profiles_includes_sqlite_and_flat() {
    let root = temp_store_root("list-mixed");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let kek = AgeKek::generate();
    let mut entries = HashMap::new();
    entries.insert("K".into(), "v".into());
    write_profile_store(&root, "app-web", &entries, &kek).unwrap();
    write_profile_store_with_backend(&root, "app-worker", &entries, &kek, StoreBackend::Sqlite)
        .unwrap();
    let names = list_stored_profiles(&root).unwrap();
    assert_eq!(names, vec!["app-web".to_string(), "app-worker".to_string()]);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn store_backend_as_str_is_stable_for_cli() {
    assert_eq!(StoreBackend::Flat.as_str(), "flat");
    assert_eq!(StoreBackend::Sqlite.as_str(), "sqlite");
}

#[test]
fn list_stored_profiles_rejects_ambiguous_dual_backend() {
    let root = temp_store_root("list-ambiguous");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(profile_store_path(&root, "app-web"), b"flat").unwrap();
    fs::write(sqlite_store_path(&root, "app-web"), b"sqlite").unwrap();
    assert!(matches!(
        list_stored_profiles(&root),
        Err(crate::core::error::Error::CatalogParse(msg)) if msg.contains("ambiguous")
    ));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn resolve_store_backend_rejects_ambiguous_profile_files() {
    let root = temp_store_root("ambiguous");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let kek = AgeKek::generate();
    let mut entries = HashMap::new();
    entries.insert("K".into(), "v".into());
    write_profile_store(&root, "app-web", &entries, &kek).unwrap();
    fs::write(
        sqlite_store_path(&root, "app-web"),
        fs::read(profile_store_path(&root, "app-web")).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        resolve_store_backend(&root, "app-web"),
        Err(crate::core::error::Error::CatalogParse(_))
    ));
    let _ = fs::remove_dir_all(&root);
}
