use std::collections::HashMap;
use std::fs;

use super::*;
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
