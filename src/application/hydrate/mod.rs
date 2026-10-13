//! **Hydrate command** — load the `github` profile from local bundles and feed
//! runtime tokens to `gh`. No SSM at hydrate time.

use std::path::PathBuf;
use std::time::Duration;

use crate::application::serve::read_entry_from_slot;
use crate::application::sync::{bundle_path, DEFAULT_STATE_DIR};
use crate::catalog::{load_catalog_snapshot, Catalog, ProfileDefinition};
use crate::core::error::Error;
use crate::core::slot::{SlotError, SlotLease, SlotTable};
use crate::legacy::profile::Kind;
use crate::ports::gh::{GhError, GhPort};
use crate::vault::kek::AgeKek;
use crate::vault::local_bundle::open_profile_into_slot;

pub const GITHUB_PROFILE: &str = "github";
pub const HYDRATE_SLOT_INDEX: usize = 3;
const HYDRATE_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydrateGhOptions {
    pub identity_path: PathBuf,
    pub state_dir: PathBuf,
}

impl HydrateGhOptions {
    pub fn new(identity_path: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            identity_path,
            state_dir,
        }
    }

    pub fn with_default_state_dir(identity_path: PathBuf) -> Self {
        Self {
            identity_path,
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
        }
    }
}

/// Open the local `github` bundle and run `gh auth login` per runtime token, then switch user.
pub fn hydrate_gh_from_vault(
    gh: &dyn GhPort,
    kek: &AgeKek,
    table: &mut SlotTable,
    options: &HydrateGhOptions,
) -> Result<(), Error> {
    let catalog = load_catalog_snapshot(&options.state_dir)?;
    hydrate_gh_with_catalog(gh, kek, table, &catalog, options)
}

pub fn hydrate_gh_with_catalog(
    gh: &dyn GhPort,
    kek: &AgeKek,
    table: &mut SlotTable,
    catalog: &Catalog,
    options: &HydrateGhOptions,
) -> Result<(), Error> {
    let definition = catalog.profile(GITHUB_PROFILE).ok_or_else(|| {
        tracing::info!(
            target: "host_env_vault::hydrate_cmd",
            profile = GITHUB_PROFILE,
            "hydrate refuse profile not in catalog"
        );
        Error::NotInCatalog(GITHUB_PROFILE.to_owned())
    })?;
    let active = definition.github_active_user.as_deref().ok_or_else(|| {
        tracing::info!(
            target: "host_env_vault::hydrate_cmd",
            profile = GITHUB_PROFILE,
            "hydrate refuse missing github active user"
        );
        Error::CatalogParse(format!(
            "profile `{GITHUB_PROFILE}` has no github_active_user"
        ))
    })?;
    let bundle_bytes = std::fs::read(bundle_path(&options.state_dir, GITHUB_PROFILE))?;
    let lease = table
        .acquire_sync(HYDRATE_SLOT_INDEX, HYDRATE_ACQUIRE_TIMEOUT)
        .map_err(map_slot_acquire)?;
    let result = (|| {
        let slot = table
            .slot_ref_mut(HYDRATE_SLOT_INDEX)
            .map_err(map_slot_acquire)?;
        let opened = open_profile_into_slot(catalog, &bundle_bytes, slot, lease, kek)?;
        if opened.profile != GITHUB_PROFILE {
            return Err(Error::ProfileMismatch {
                found: opened.profile,
                expected: GITHUB_PROFILE.to_owned(),
            });
        }
        login_runtime_tokens(gh, definition, slot, lease)?;
        gh.auth_switch_user(active).map_err(map_gh)?;
        tracing::info!(
            target: "host_env_vault::hydrate_cmd",
            profile = GITHUB_PROFILE,
            active_user = active,
            "hydrate gh switched active user"
        );
        Ok(())
    })();
    let _ = table.release(lease);
    result
}

fn login_runtime_tokens(
    gh: &dyn GhPort,
    definition: &ProfileDefinition,
    slot: &crate::core::slot::Slot,
    lease: SlotLease,
) -> Result<(), Error> {
    for account in definition.runtime_env() {
        let token = read_entry_from_slot(slot, lease, Kind::Env, account)?;
        gh.auth_login_with_token(&token).map_err(map_gh)?;
        tracing::info!(
            target: "host_env_vault::hydrate_cmd",
            profile = GITHUB_PROFILE,
            account = %account,
            "hydrate gh logged in account"
        );
    }
    Ok(())
}

fn map_gh(err: GhError) -> Error {
    match err {
        GhError::LoginFailed => Error::CatalogParse("gh auth login failed".into()),
        GhError::SwitchFailed => Error::CatalogParse("gh auth switch failed".into()),
        GhError::Unavailable => Error::CatalogParse("gh unavailable".into()),
    }
}

fn map_slot_acquire(err: SlotError) -> Error {
    Error::CatalogParse(format!("hydrate slot acquire: {err:?}"))
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod log_tests;

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn hydrate_slot_is_distinct_from_other_commands() {
        assert_eq!(crate::application::sync::SYNC_SLOT_INDEX, 0);
        assert_eq!(crate::application::render::RENDER_SLOT_INDEX, 1);
        assert_eq!(crate::application::serve::SERVE_SLOT_INDEX, 2);
        assert_eq!(HYDRATE_SLOT_INDEX, 3);
        assert!(HYDRATE_SLOT_INDEX < crate::core::slot::SLOT_COUNT);
    }
}
