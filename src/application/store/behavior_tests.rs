use std::fs;

use crate::application::store::{
    mask_secret, resolve_field, store_get, store_import_from_dev_dir, store_import_from_env_file,
    store_init, store_list, store_put, store_remove, store_rekey, StoreOptions,
};
use crate::core::error::Error;
use crate::ports::LOCAL_CATALOG_FILE;
use crate::vault::host_store::{profile_store_path, read_profile_store};
use crate::vault::kek::AgeKek;

fn temp_root(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-store-crud-{label}-{}-{id}",
        std::process::id()
    ))
}

fn options(root: &std::path::Path) -> StoreOptions {
    StoreOptions {
        identity_path: root.join("kek.age"),
        store_dir: root.join("store"),
    }
}

#[test]
fn store_put_get_list_remove_round_trip() {
    let root = temp_root("crud");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    store_init(&opts).unwrap();
    store_put(&opts, "app-web", "DB_PASS", "secret", &kek).unwrap();
    assert_eq!(
        store_get(&opts, "app-web", "DB_PASS", &kek, true).unwrap(),
        "secret"
    );
    assert!(store_get(&opts, "app-web", "DB_PASS", &kek, false)
        .unwrap()
        .starts_with("***"));
    let listed = store_list(&opts, &kek).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].profile, "app-web");
    assert_eq!(listed[0].entries, vec!["DB_PASS".to_string()]);
    store_remove(&opts, "app-web", "DB_PASS", &kek).unwrap();
    assert!(!profile_store_path(&opts.store_dir, "app-web").is_file());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn store_import_from_dev_dir_uses_catalog_entries() {
    let root = temp_root("import-dev");
    let dev = temp_root("import-dev-src");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&dev);
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&dev).unwrap();
    const CATALOG: &str =
        r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#;
    fs::write(dev.join(LOCAL_CATALOG_FILE), CATALOG).unwrap();
    fs::write(dev.join("app-web.env"), "DB_PASS=from-dev\n").unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    store_init(&opts).unwrap();
    let count = store_import_from_dev_dir(&opts, &dev, None, &kek).unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        read_profile_store(&opts.store_dir, "app-web", &kek).unwrap()["DB_PASS"],
        "from-dev"
    );
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&dev);
}

#[test]
fn store_import_from_env_file_reads_at_paths() {
    let root = temp_root("import-env");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("token.pem"), "pem-bytes").unwrap();
    fs::write(
        root.join("app-web.env"),
        "API_TOKEN=@token.pem\n# skip\n\n",
    )
    .unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    store_init(&opts).unwrap();
    let count =
        store_import_from_env_file(&opts, "app-web", &root.join("app-web.env"), &kek).unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        read_profile_store(&opts.store_dir, "app-web", &kek).unwrap()["API_TOKEN"],
        "pem-bytes"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn store_rekey_reseals_all_profiles() {
    let root = temp_root("rekey");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let old = AgeKek::generate();
    let new = AgeKek::generate();
    store_put(&opts, "app-web", "K", "v", &old).unwrap();
    let before = fs::read(profile_store_path(&opts.store_dir, "app-web")).unwrap();
    store_rekey(&opts, &old, &new).unwrap();
    let after = fs::read(profile_store_path(&opts.store_dir, "app-web")).unwrap();
    assert_ne!(before, after);
    assert_eq!(
        read_profile_store(&opts.store_dir, "app-web", &new).unwrap()["K"],
        "v"
    );
    assert!(read_profile_store(&opts.store_dir, "app-web", &old).is_err());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn mask_secret_formats_length() {
    assert_eq!(mask_secret(""), "(empty)");
    assert_eq!(mask_secret("abc"), "*** (3 bytes)");
}

#[test]
fn store_import_from_dev_dir_honors_profile_filter() {
    let root = temp_root("import-filter");
    let dev = temp_root("import-filter-dev");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&dev);
    fs::create_dir_all(&dev).unwrap();
    const CATALOG: &str = r#"{"profiles":[
        {"name":"app-web","inject":["A"],"runtime":[]},
        {"name":"app-worker","inject":["B"],"runtime":[]}
    ]}"#;
    fs::write(dev.join(LOCAL_CATALOG_FILE), CATALOG).unwrap();
    fs::write(dev.join("app-web.env"), "A=1\n").unwrap();
    fs::write(dev.join("app-worker.env"), "B=2\n").unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    let count = store_import_from_dev_dir(&opts, &dev, Some("app-web"), &kek).unwrap();
    assert_eq!(count, 1);
    assert!(read_profile_store(&opts.store_dir, "app-web", &kek).is_ok());
    assert!(read_profile_store(&opts.store_dir, "app-worker", &kek).is_err());
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&dev);
}

#[test]
fn store_import_from_env_file_missing_path_errors() {
    let root = temp_root("import-missing");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    assert!(matches!(
        store_import_from_env_file(&opts, "app-web", &root.join("missing.env"), &kek),
        Err(Error::SsmMissing(_))
    ));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn store_import_from_env_file_skips_when_no_entries() {
    let root = temp_root("import-empty");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("app-web.env"), "# only comments\n\n").unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    let count =
        store_import_from_env_file(&opts, "app-web", &root.join("app-web.env"), &kek).unwrap();
    assert_eq!(count, 0);
    assert!(!profile_store_path(&opts.store_dir, "app-web").is_file());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn store_rekey_counts_every_profile_file() {
    let root = temp_root("rekey-count");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let old = AgeKek::generate();
    let new = AgeKek::generate();
    store_put(&opts, "app-web", "K", "v", &old).unwrap();
    store_put(&opts, "app-worker", "K", "v", &old).unwrap();
    assert_eq!(store_rekey(&opts, &old, &new).unwrap(), 2);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn store_put_rejects_invalid_profile_or_entry_names() {
    let root = temp_root("validate-names");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    assert!(matches!(
        store_put(&opts, "../bad", "DB_PASS", "x", &kek),
        Err(Error::CatalogParse(_))
    ));
    assert!(matches!(
        store_put(&opts, "app-web", "../bad", "x", &kek),
        Err(Error::CatalogParse(_))
    ));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn resolve_field_uses_flag_and_rejects_empty_non_interactive() {
    assert_eq!(
        resolve_field("profile", Some("app-web".into()), true).unwrap(),
        "app-web"
    );
    assert!(matches!(
        resolve_field("profile", None, true),
        Err(Error::CatalogParse(_))
    ));
    assert!(matches!(
        resolve_field("profile", Some(String::new()), true),
        Err(Error::CatalogParse(_))
    ));
}
