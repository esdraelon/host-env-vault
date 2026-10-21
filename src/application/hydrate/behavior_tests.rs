use std::path::PathBuf;

use crate::application::hydrate::{
    hydrate_gh_from_vault, hydrate_gh_with_catalog, HydrateGhOptions, GITHUB_PROFILE,
    HYDRATE_SLOT_INDEX,
};
use crate::application::manifest::seed_manifests_for_catalog_text;
use crate::application::sync::{sync_from_ssm, SyncOptions, SYNC_SLOT_INDEX};
use crate::catalog::{parse_catalog_text, write_catalog_snapshot, SealEntry};
use crate::core::slot::SlotTable;
use crate::legacy::profile::Kind;
use crate::ports::{MemoryGh, MemorySsm};
use crate::vault::kek::AgeKek;
use crate::vault::local_bundle::seal_profile_in_slot;

const GITHUB_CATALOG: &str = r#"{"profiles":[{"name":"github","inject":[],"runtime":["gh-user-alpha","gh-user-beta"],"github_active_user":"gh-user-alpha"}]}"#;

fn temp_state_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("hev-hydrate-{label}-{}-{id}", std::process::id()))
}

fn seal_github_bundle(state_dir: &PathBuf, kek: &AgeKek) {
    let catalog = parse_catalog_text(GITHUB_CATALOG).unwrap();
    let mut table = SlotTable::new();
    let lease = table
        .try_acquire(SYNC_SLOT_INDEX, std::time::Instant::now())
        .unwrap();
    let slot = table.slot_ref_mut(SYNC_SLOT_INDEX).unwrap();
    let entries = [
        SealEntry {
            name: "gh-user-alpha".into(),
            kind: Kind::Env,
            bytes: b"gho_gh-user-alpha_token",
        },
        SealEntry {
            name: "gh-user-beta".into(),
            kind: Kind::Env,
            bytes: b"gho_gh-user-beta_token",
        },
    ];
    let bundle =
        seal_profile_in_slot(&catalog, slot, lease, GITHUB_PROFILE, &entries, kek).unwrap();
    let _ = table.release(lease);
    std::fs::write(
        crate::application::sync::bundle_path(state_dir, GITHUB_PROFILE),
        bundle,
    )
    .unwrap();
}

#[test]
fn hydrate_gh_feeds_each_token_and_switches_active_user() {
    let state_dir = temp_state_dir("happy");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    write_catalog_snapshot(&state_dir, GITHUB_CATALOG).unwrap();
    let kek = AgeKek::generate();
    seal_github_bundle(&state_dir, &kek);
    let gh = MemoryGh::new();
    let mut table = SlotTable::new();
    let options = HydrateGhOptions::new(state_dir.join("kek.age"), state_dir.clone());
    hydrate_gh_from_vault(&gh, &kek, &mut table, &options).unwrap();
    assert_eq!(
        gh.login_tokens(),
        vec![
            b"gho_gh-user-alpha_token".to_vec(),
            b"gho_gh-user-beta_token".to_vec()
        ]
    );
    assert_eq!(gh.switch_user().as_deref(), Some("gh-user-alpha"));
    assert!(!table.slot_ref(HYDRATE_SLOT_INDEX).unwrap().in_use());
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn hydrate_gh_refuses_missing_github_profile_in_catalog() {
    let state_dir = temp_state_dir("no-github");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    write_catalog_snapshot(
        &state_dir,
        r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[]}]}"#,
    )
    .unwrap();
    let gh = MemoryGh::new();
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let options = HydrateGhOptions::new(state_dir.join("kek.age"), state_dir.clone());
    assert!(matches!(
        hydrate_gh_from_vault(&gh, &kek, &mut table, &options),
        Err(crate::core::error::Error::NotInCatalog(_))
    ));
    assert!(gh.login_tokens().is_empty());
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn hydrate_gh_refuses_catalog_without_active_user() {
    let state_dir = temp_state_dir("no-active");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    let catalog_json = r#"{"profiles":[{"name":"github","inject":[],"runtime":["gh-user-alpha"]}]}"#;
    write_catalog_snapshot(&state_dir, catalog_json).unwrap();
    let kek = AgeKek::generate();
    seal_github_bundle(&state_dir, &kek);
    let gh = MemoryGh::new();
    let mut table = SlotTable::new();
    let options = HydrateGhOptions::new(state_dir.join("kek.age"), state_dir.clone());
    assert!(matches!(
        hydrate_gh_from_vault(&gh, &kek, &mut table, &options),
        Err(crate::core::error::Error::CatalogParse(_))
    ));
    assert!(gh.login_tokens().is_empty());
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn hydrate_gh_propagates_gh_switch_failure() {
    let state_dir = temp_state_dir("switch-fail");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    write_catalog_snapshot(&state_dir, GITHUB_CATALOG).unwrap();
    let kek = AgeKek::generate();
    seal_github_bundle(&state_dir, &kek);
    let gh = MemoryGh::new();
    gh.fail_switch();
    let mut table = SlotTable::new();
    let options = HydrateGhOptions::new(state_dir.join("kek.age"), state_dir.clone());
    assert!(matches!(
        hydrate_gh_from_vault(&gh, &kek, &mut table, &options),
        Err(crate::core::error::Error::CatalogParse(_))
    ));
    assert_eq!(gh.login_tokens().len(), 2);
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn hydrate_gh_propagates_gh_login_failure() {
    let state_dir = temp_state_dir("login-fail");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    write_catalog_snapshot(&state_dir, GITHUB_CATALOG).unwrap();
    let kek = AgeKek::generate();
    seal_github_bundle(&state_dir, &kek);
    let gh = MemoryGh::new();
    gh.fail_login();
    let mut table = SlotTable::new();
    let options = HydrateGhOptions::new(state_dir.join("kek.age"), state_dir.clone());
    assert!(matches!(
        hydrate_gh_from_vault(&gh, &kek, &mut table, &options),
        Err(crate::core::error::Error::CatalogParse(_))
    ));
    assert!(gh.login_tokens().is_empty());
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn hydrate_gh_after_sync_does_not_call_ssm() {
    let state_dir = temp_state_dir("post-sync");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    let ssm = MemorySsm::new();
    ssm.put(crate::catalog::DEFAULT_CATALOG_PARAMETER, GITHUB_CATALOG);
    ssm.put("/host-env-vault/github/gh-user-alpha", "gho_gh-user-alpha_token");
    ssm.put("/host-env-vault/github/gh-user-beta", "gho_gh-user-beta_token");
    let kek = AgeKek::generate();
    let identity = state_dir.join("kek.age");
    kek.write_identity(&identity).unwrap();
    seed_manifests_for_catalog_text(&state_dir, GITHUB_CATALOG).unwrap();
    let mut table = SlotTable::new();
    let sync_options = SyncOptions::new(
        identity.clone(),
        state_dir.clone(),
        crate::catalog::DEFAULT_CATALOG_PARAMETER.to_owned(),
        crate::catalog::DEFAULT_SECRETS_PREFIX.to_owned(),
    );
    sync_from_ssm(&ssm, &kek, &mut table, &sync_options).unwrap();

    let gh = MemoryGh::new();
    let catalog = parse_catalog_text(GITHUB_CATALOG).unwrap();
    let options = HydrateGhOptions::new(identity, state_dir.clone());
    hydrate_gh_with_catalog(&gh, &kek, &mut table, &catalog, &options).unwrap();
    assert_eq!(gh.login_tokens().len(), 2);
    assert_eq!(gh.switch_user().as_deref(), Some("gh-user-alpha"));
    let _ = std::fs::remove_dir_all(&state_dir);
}
