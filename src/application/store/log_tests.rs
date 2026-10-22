use serial_test::serial;
use std::fs;

use crate::application::store::{
    store_import_from_dev_dir, store_init, store_put, store_rekey, StoreOptions,
};
use crate::ports::LOCAL_CATALOG_FILE;
use crate::testing::log_test_capture::capture_info_logs;
use crate::vault::kek::AgeKek;

fn temp_root(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-store-log-{label}-{}-{id}",
        std::process::id()
    ))
}

fn options(root: &std::path::Path) -> StoreOptions {
    StoreOptions {
        identity_path: root.join("kek.age"),
        store_dir: root.join("store"),
    }
}

#[serial]
#[test]
fn log_store_init_layout_ready() {
    let root = temp_root("init-log");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let text = capture_info_logs(|| {
        store_init(&opts).unwrap();
    });
    assert!(
        text.contains("store init: layout ready"),
        "logs: {text}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[serial]
#[test]
fn log_store_put_upserted() {
    let root = temp_root("put-log");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    let text = capture_info_logs(|| {
        store_put(&opts, "app-web", "DB_PASS", "x", &kek).unwrap();
    });
    assert!(
        text.contains("store put: entry upserted"),
        "logs: {text}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[serial]
#[test]
fn log_store_import_dev_layout() {
    let root = temp_root("import-log");
    let dev = temp_root("import-log-dev");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&dev);
    fs::create_dir_all(&dev).unwrap();
    const CATALOG: &str =
        r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#;
    fs::write(dev.join(LOCAL_CATALOG_FILE), CATALOG).unwrap();
    fs::write(dev.join("app-web.env"), "DB_PASS=v\n").unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    let text = capture_info_logs(|| {
        store_import_from_dev_dir(&opts, &dev, None, &kek).unwrap();
    });
    assert!(
        text.contains("store import: dev layout complete"),
        "logs: {text}"
    );
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&dev);
}

#[serial]
#[test]
fn log_store_rekey_rotated() {
    let root = temp_root("rekey-log");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let old = AgeKek::generate();
    let new = AgeKek::generate();
    store_put(&opts, "app-web", "K", "v", &old).unwrap();
    let text = capture_info_logs(|| {
        store_rekey(&opts, &old, &new).unwrap();
    });
    assert!(
        text.contains("store rekey: profiles rotated"),
        "logs: {text}"
    );
    let _ = fs::remove_dir_all(&root);
}
