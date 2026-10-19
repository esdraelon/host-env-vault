use std::path::PathBuf;

use crate::application::manifest::{
    default_manifests_dir, preflight_profile_manifest, strict_cross_check, write_manifest_for_profile,
    ManifestDiscovery, ProfileManifest,
};
use crate::catalog::parse_catalog_text;
use crate::config::SyncSourceKind;
use crate::core::error::Error;

const WEB: &str = r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#;

fn temp_root(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("hev-manifest-{label}-{}-{id}", std::process::id()))
}

#[test]
fn strict_cross_check_rejects_catalog_only_entry() {
    let catalog = parse_catalog_text(WEB).unwrap();
    let def = catalog.profile("app-web").unwrap();
    let manifest = ProfileManifest {
        profile: "app-web".into(),
        inject_env: vec![],
        inject_files: vec![],
        runtime_env: vec![],
        runtime_files: vec![],
    };
    assert!(matches!(
        strict_cross_check(def, &manifest),
        Err(Error::ManifestMismatch { .. })
    ));
}

#[test]
fn discovery_prefers_local_secrets_dir_when_source_local() {
    let root = temp_root("local-prefer");
    let _ = std::fs::remove_dir_all(&root);
    let secrets = root.join("secrets");
    let state = root.join("state");
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::create_dir_all(state.join("manifests")).unwrap();
    let catalog = parse_catalog_text(WEB).unwrap();
    let def = catalog.profile("app-web").unwrap();
    write_manifest_for_profile(&secrets, def).unwrap();
    std::fs::write(
        state.join("manifests/app-web.env-host-vault"),
        "profile = \"wrong\"\n[inject]\nenv = []\nfiles = []\n[runtime]\nenv = []\nfiles = []\n",
    )
    .unwrap();
    let discovery = ManifestDiscovery::new(
        SyncSourceKind::Local,
        &state,
        Some(secrets.clone()),
        None,
    );
    preflight_profile_manifest(&discovery, def).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn default_manifests_dir_is_under_state() {
    assert_eq!(
        default_manifests_dir(std::path::Path::new("/var/lib/host-env-vault")),
        PathBuf::from("/var/lib/host-env-vault/manifests")
    );
}
