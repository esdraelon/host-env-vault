//! **Sync command** — pull catalog and secrets from SSM, seal local bundles.
//! One profile occupies the sync slot at a time; a failed pull keeps the prior `.hev`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::catalog::{
    parse_catalog_text, write_catalog_snapshot, Catalog, ProfileDefinition, SealEntry,
};
use crate::catalog::DEFAULT_CATALOG_PARAMETER;
use crate::error::Error;
use crate::kek::AgeKek;
use crate::local_bundle::seal_profile_in_slot;
use crate::port::ssm::{SsmError, SsmPort};
use crate::profile::{valid_env_value, Kind};
use crate::slot::{SlotTable, SECRET_MAX_BYTES};

pub const DEFAULT_STATE_DIR: &str = "/var/lib/host-env-vault";
pub const SYNC_SLOT_INDEX: usize = 0;
const SYNC_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);

/// Paths and parameter names for a sync run. `state_dir` is overridable in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOptions {
    pub identity_path: PathBuf,
    pub state_dir: PathBuf,
    pub catalog_param: String,
}

impl SyncOptions {
    pub fn new(identity_path: PathBuf, state_dir: PathBuf, catalog_param: String) -> Self {
        Self {
            identity_path,
            state_dir,
            catalog_param,
        }
    }

    pub fn with_defaults(identity_path: PathBuf) -> Self {
        Self {
            identity_path,
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
        }
    }
}

/// Local bundle path for a catalog profile name.
pub fn bundle_path(state_dir: &Path, profile_name: &str) -> PathBuf {
    state_dir.join(format!("{profile_name}.hev"))
}

/// SSM parameter path for one secret entry under a profile.
pub fn ssm_entry_parameter(profile_name: &str, entry_name: &str) -> String {
    format!("/amtgard/{profile_name}/{entry_name}")
}

/// Read the age identity or mint a new one on first sync.
pub fn load_or_create_identity(path: &Path) -> Result<AgeKek, Error> {
    if path.exists() {
        return AgeKek::read_identity(path);
    }
    let kek = AgeKek::generate();
    kek.write_identity(path)?;
    tracing::info!(
        target: "host_env_vault::sync",
        path = %path.display(),
        "sync created host identity"
    );
    Ok(kek)
}

/// Pull the catalog and seal every profile into `state_dir`.
pub fn sync_from_ssm(
    ssm: &dyn SsmPort,
    kek: &AgeKek,
    table: &mut SlotTable,
    options: &SyncOptions,
) -> Result<(), Error> {
    let catalog = pull_and_persist_catalog(ssm, &options.catalog_param, &options.state_dir)?;
    tracing::info!(
        target: "host_env_vault::sync",
        profile_count = catalog.profile_names().count(),
        "sync catalog loaded"
    );
    std::fs::create_dir_all(&options.state_dir)?;
    let mut names: Vec<_> = catalog.profile_names().collect();
    names.sort_unstable();
    let mut failures = 0usize;
    for profile_name in names {
        match sync_one_profile(ssm, kek, table, &catalog, profile_name, &options.state_dir) {
            Ok(()) => {}
            Err(err) => {
                failures += 1;
                tracing::info!(
                    target: "host_env_vault::sync",
                    profile = profile_name,
                    error = %err,
                    "sync profile failed keeping bundle"
                );
            }
        }
    }
    if failures > 0 {
        return Err(Error::SyncFailed { count: failures });
    }
    Ok(())
}

fn sync_one_profile(
    ssm: &dyn SsmPort,
    kek: &AgeKek,
    table: &mut SlotTable,
    catalog: &Catalog,
    profile_name: &str,
    state_dir: &Path,
) -> Result<(), Error> {
    let definition = catalog
        .profile(profile_name)
        .ok_or_else(|| Error::NotInCatalog(profile_name.to_owned()))?;
    let pulled = pull_profile_entries(ssm, definition)?;
    let seal_entries = seal_entries_from_pulled(&pulled);
    let lease = table
        .acquire_sync(SYNC_SLOT_INDEX, SYNC_ACQUIRE_TIMEOUT)
        .map_err(map_slot_acquire)?;
    let seal_result = (|| {
        let slot = table
            .slot_ref_mut(SYNC_SLOT_INDEX)
            .map_err(map_slot_acquire)?;
        let bundle = seal_profile_in_slot(
            catalog,
            slot,
            lease,
            profile_name,
            &seal_entries,
            kek,
        )?;
        write_bundle_atomically(&bundle_path(state_dir, profile_name), &bundle)?;
        tracing::info!(
            target: "host_env_vault::sync",
            profile = profile_name,
            bytes = bundle.len(),
            "sync profile sealed replacing bundle"
        );
        Ok::<(), Error>(())
    })();
    let _ = table.release(lease);
    seal_result
}

struct PulledEntry {
    name: String,
    kind: Kind,
    bytes: Zeroizing<Vec<u8>>,
}

fn pull_profile_entries(
    ssm: &dyn SsmPort,
    definition: &ProfileDefinition,
) -> Result<Vec<PulledEntry>, Error> {
    let mut entries = Vec::new();
    for name in definition.inject_env() {
        entries.push(fetch_pulled_entry(ssm, &definition.name, name, Kind::Env)?);
    }
    for name in definition.runtime_env() {
        entries.push(fetch_pulled_entry(ssm, &definition.name, name, Kind::Env)?);
    }
    for name in definition.inject_files() {
        entries.push(fetch_pulled_entry(ssm, &definition.name, name, Kind::File)?);
    }
    for name in definition.runtime_files() {
        entries.push(fetch_pulled_entry(ssm, &definition.name, name, Kind::File)?);
    }
    if entries.is_empty() {
        return Err(Error::EmptyBundle);
    }
    Ok(entries)
}

fn seal_entries_from_pulled(pulled: &[PulledEntry]) -> Vec<SealEntry<'_>> {
    pulled
        .iter()
        .map(|entry| SealEntry {
            name: entry.name.clone(),
            kind: entry.kind,
            bytes: &entry.bytes,
        })
        .collect()
}

fn fetch_pulled_entry(
    ssm: &dyn SsmPort,
    profile_name: &str,
    entry_name: &str,
    kind: Kind,
) -> Result<PulledEntry, Error> {
    let param = ssm_entry_parameter(profile_name, entry_name);
    let text = ssm.get_parameter(&param).map_err(map_ssm)?;
    let bytes = text.into_bytes();
    let max = match kind {
        Kind::Env => SECRET_MAX_BYTES,
        Kind::File => SECRET_MAX_BYTES,
    };
    if bytes.len() > max {
        tracing::info!(
            target: "host_env_vault::sync",
            profile = profile_name,
            entry = entry_name,
            len = bytes.len(),
            max,
            "sync reject oversize parameter"
        );
        return Err(Error::RuntimeBody);
    }
    if kind == Kind::Env && !valid_env_value(&bytes) {
        return Err(Error::InvalidEnvValue(entry_name.to_owned()));
    }
    Ok(PulledEntry {
        name: entry_name.to_owned(),
        kind,
        bytes: Zeroizing::new(bytes),
    })
}

fn write_bundle_atomically(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("hev.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn pull_and_persist_catalog(
    ssm: &dyn SsmPort,
    catalog_param: &str,
    state_dir: &Path,
) -> Result<Catalog, Error> {
    let text = ssm.get_parameter(catalog_param).map_err(map_ssm)?;
    write_catalog_snapshot(state_dir, &text)?;
    parse_catalog_text(&text)
}

fn map_ssm(err: SsmError) -> Error {
    match err {
        SsmError::NotFound(name) => Error::SsmMissing(name),
        SsmError::Unavailable => Error::CatalogParse("ssm unavailable".into()),
    }
}

fn map_slot_acquire(err: crate::slot::SlotError) -> Error {
    Error::CatalogParse(format!("sync slot acquire: {err:?}"))
}

/// Test hook: parse catalog text without SSM.
pub fn sync_catalog_from_text(
    text: &str,
    ssm: &dyn SsmPort,
    kek: &AgeKek,
    table: &mut SlotTable,
    state_dir: &Path,
) -> Result<(), Error> {
    std::fs::create_dir_all(state_dir)?;
    write_catalog_snapshot(state_dir, text)?;
    let catalog = parse_catalog_text(text)?;
    let mut names: Vec<_> = catalog.profile_names().collect();
    names.sort_unstable();
    let mut failures = 0usize;
    for profile_name in names {
        if sync_one_profile(ssm, kek, table, &catalog, profile_name, state_dir).is_err() {
            failures += 1;
        }
    }
    if failures > 0 {
        return Err(Error::SyncFailed { count: failures });
    }
    Ok(())
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod log_tests;

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn bundle_and_ssm_paths_follow_plan_layout() {
        assert_eq!(
            bundle_path(Path::new("/var/lib/host-env-vault"), "denarius-web"),
            PathBuf::from("/var/lib/host-env-vault/denarius-web.hev")
        );
        assert_eq!(
            ssm_entry_parameter("denarius-web", "DB_PASS"),
            "/amtgard/denarius-web/DB_PASS"
        );
    }

    #[test]
    fn sync_slot_index_is_first_worker_slot() {
        assert_eq!(SYNC_SLOT_INDEX, 0);
        assert!(SYNC_SLOT_INDEX < crate::slot::SLOT_COUNT);
    }
}
