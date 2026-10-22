use std::fs;

use sha2::{Digest, Sha256};

use crate::application::store::{
    store_export_ssm, store_put, StoreExportOutput, StoreExportSsmOptions, StoreOptions,
};
use crate::ports::ssm_entry_parameter;
use crate::vault::kek::AgeKek;

fn temp_root(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-store-export-{label}-{}-{id}",
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
fn store_export_ssm_dry_run_prints_paths_and_sha256() {
    let root = temp_root("dry-run");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    store_put(&opts, "app-web", "DB_PASS", "secret-value", &kek).unwrap();
    let prefix = "/host-env-vault";
    let out = store_export_ssm(
        &opts,
        &StoreExportSsmOptions {
            secrets_prefix: prefix.into(),
            dry_run: true,
            output: StoreExportOutput::Script,
            profile_filter: None,
        },
        &kek,
    )
    .unwrap();
    let param = ssm_entry_parameter(prefix, "app-web", "DB_PASS");
    let hash = format!("{:x}", Sha256::digest(b"secret-value"));
    assert!(out.contains(&param));
    assert!(out.contains(&format!("sha256={hash}")));
    assert!(!out.contains("aws ssm"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn store_export_ssm_script_emits_put_parameter() {
    let root = temp_root("script");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    store_put(&opts, "app-web", "TOKEN", "tok", &kek).unwrap();
    let out = store_export_ssm(
        &opts,
        &StoreExportSsmOptions {
            secrets_prefix: "/hev".into(),
            dry_run: false,
            output: StoreExportOutput::Script,
            profile_filter: None,
        },
        &kek,
    )
    .unwrap();
    assert!(out.starts_with("#!/usr/bin/env bash"));
    assert!(out.contains("aws ssm put-parameter"));
    assert!(out.contains("/hev/app-web/TOKEN"));
    assert!(out.contains("'tok'"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn store_export_ssm_json_manifest_uses_sha256_not_plaintext() {
    let root = temp_root("json");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    store_put(&opts, "app-worker", "K", "plain", &kek).unwrap();
    let out = store_export_ssm(
        &opts,
        &StoreExportSsmOptions {
            secrets_prefix: "/host-env-vault".into(),
            dry_run: false,
            output: StoreExportOutput::JsonManifest,
            profile_filter: None,
        },
        &kek,
    )
    .unwrap();
    let hash = format!("{:x}", Sha256::digest(b"plain"));
    assert!(out.contains(&hash));
    assert!(!out.contains("plain"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn store_export_ssm_honors_profile_filter() {
    let root = temp_root("filter");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let opts = options(&root);
    let kek = AgeKek::generate();
    store_put(&opts, "app-web", "A", "1", &kek).unwrap();
    store_put(&opts, "app-worker", "B", "2", &kek).unwrap();
    let out = store_export_ssm(
        &opts,
        &StoreExportSsmOptions {
            secrets_prefix: "/p".into(),
            dry_run: true,
            output: StoreExportOutput::Script,
            profile_filter: Some("app-web".into()),
        },
        &kek,
    )
    .unwrap();
    assert!(out.contains("/p/app-web/A"));
    assert!(!out.contains("app-worker"));
    let _ = fs::remove_dir_all(&root);
}
