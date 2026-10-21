//! **Sync command** — pull catalog and secrets from SSM, seal local bundles.
//! One profile occupies the sync slot at a time; a failed pull keeps the prior `.hev`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::application::documents::pull_profile_documents;
use crate::application::manifest::{
    clear_stale_marker, preflight_profile_manifest, write_stale_marker, ManifestDiscovery,
};
use crate::catalog::{DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};
use crate::config::SyncSourceKind;
use crate::catalog::{
    parse_catalog_text, write_catalog_snapshot, Catalog, ProfileDefinition, SealEntry,
};
use crate::core::error::Error;
use crate::core::slot::{SlotTable, SECRET_MAX_BYTES};
use crate::legacy::profile::{valid_env_value, Kind};
use crate::ports::s3::S3Port;
use crate::ports::secret_source::{
    HostStoreSecretSource, LocalSecretSource, SecretSource, SsmSecretSource,
};
use crate::ports::ssm::SsmPort;
use crate::vault::kek::AgeKek;
use crate::vault::local_bundle::seal_profile_in_slot;

pub const DEFAULT_STATE_DIR: &str = "/var/lib/host-env-vault";
pub const SYNC_SLOT_INDEX: usize = 0;
const SYNC_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);

/// Paths and parameter names for a sync run. `state_dir` is overridable in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOptions {
    pub identity_path: PathBuf,
    pub state_dir: PathBuf,
    pub catalog_param: String,
    pub secrets_prefix: String,
    pub source: SyncSourceKind,
    pub local_secrets_dir: Option<PathBuf>,
    pub manifests_dir: Option<PathBuf>,
    /// When set with [`SyncOptions::s3_prefix`], catalog document keys are pulled from S3.
    pub s3_prefix: Option<String>,
}

impl SyncOptions {
    pub fn new(
        identity_path: PathBuf,
        state_dir: PathBuf,
        catalog_param: String,
        secrets_prefix: String,
    ) -> Self {
        Self {
            identity_path,
            state_dir,
            catalog_param,
            secrets_prefix,
            source: SyncSourceKind::Ssm,
            local_secrets_dir: None,
            manifests_dir: None,
            s3_prefix: None,
        }
    }

    pub fn with_defaults(identity_path: PathBuf) -> Self {
        Self {
            identity_path,
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
            source: SyncSourceKind::Ssm,
            local_secrets_dir: None,
            manifests_dir: None,
            s3_prefix: None,
        }
    }

    pub fn with_manifest_lookup(
        mut self,
        source: SyncSourceKind,
        local_secrets_dir: Option<PathBuf>,
        manifests_dir: Option<PathBuf>,
    ) -> Self {
        self.source = source;
        self.local_secrets_dir = local_secrets_dir;
        self.manifests_dir = manifests_dir;
        self
    }

    pub fn with_s3_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.s3_prefix = Some(prefix.into());
        self
    }
}

/// Local bundle path for a catalog profile name.
pub fn bundle_path(state_dir: &Path, profile_name: &str) -> PathBuf {
    state_dir.join(format!("{profile_name}.hev"))
}

pub use crate::ports::secret_source::ssm_entry_parameter;

/// Read the age identity or mint a new one on first sync.
pub fn load_or_create_identity(path: &Path) -> Result<AgeKek, Error> {
    if path.exists() {
        return AgeKek::read_identity(path);
    }
    let kek = AgeKek::generate();
    kek.write_identity(path)?;
    tracing::info!(
        target: "host_env_vault::application::sync",
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
    sync_from_ports(ssm, None, kek, table, options)
}

/// Pull catalog and secrets from a local dev directory (no AWS SSM).
pub fn sync_from_local(
    local_secrets_dir: &Path,
    s3: Option<&dyn S3Port>,
    kek: &AgeKek,
    table: &mut SlotTable,
    options: &SyncOptions,
) -> Result<(), Error> {
    let secrets = LocalSecretSource::new(local_secrets_dir);
    sync_from_secret_source(&secrets, s3, kek, table, options)
}

/// Pull catalog (SSM or local) and entries from encrypted host store files into bundles.
pub fn sync_from_host_store(
    catalog: &dyn SecretSource,
    store_dir: &Path,
    kek: &AgeKek,
    s3: Option<&dyn S3Port>,
    table: &mut SlotTable,
    options: &SyncOptions,
) -> Result<(), Error> {
    tracing::info!(
        target: "host_env_vault::application::sync",
        store_dir = %store_dir.display(),
        "sync transition mode: host encrypted store active"
    );
    let secrets = HostStoreSecretSource::new(catalog, store_dir, kek);
    sync_from_secret_source(&secrets, s3, kek, table, options)
}

/// Pull catalog and secrets from SSM and optional S3 documents into local bundles.
pub fn sync_from_ports(
    ssm: &dyn SsmPort,
    s3: Option<&dyn S3Port>,
    kek: &AgeKek,
    table: &mut SlotTable,
    options: &SyncOptions,
) -> Result<(), Error> {
    let secrets = SsmSecretSource::new(
        &options.catalog_param,
        &options.secrets_prefix,
        ssm,
    );
    sync_from_secret_source(&secrets, s3, kek, table, options)
}

/// Pull catalog and secrets from a [`SecretSource`] and optional S3 documents into local bundles.
pub fn sync_from_secret_source(
    secrets: &dyn SecretSource,
    s3: Option<&dyn S3Port>,
    kek: &AgeKek,
    table: &mut SlotTable,
    options: &SyncOptions,
) -> Result<(), Error> {
    let catalog = pull_and_persist_catalog(secrets, &options.state_dir)?;
    tracing::info!(
        target: "host_env_vault::application::sync",
        profile_count = catalog.profile_names().count(),
        "sync catalog loaded"
    );
    std::fs::create_dir_all(&options.state_dir)?;
    let mut names: Vec<_> = catalog.profile_names().collect();
    names.sort_unstable();
    let mut failures = 0usize;
    let manifest_discovery = ManifestDiscovery::new(
        options.source,
        &options.state_dir,
        options.local_secrets_dir.clone(),
        options.manifests_dir.clone(),
    );
    for profile_name in names {
        match sync_one_profile(
            secrets,
            s3,
            options.s3_prefix.as_deref(),
            kek,
            table,
            &catalog,
            profile_name,
            &options.state_dir,
            &manifest_discovery,
        ) {
            Ok(()) => {}
            Err(err) => {
                failures += 1;
                tracing::info!(
                    target: "host_env_vault::application::sync",
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
    secrets: &dyn SecretSource,
    s3: Option<&dyn S3Port>,
    s3_prefix: Option<&str>,
    kek: &AgeKek,
    table: &mut SlotTable,
    catalog: &Catalog,
    profile_name: &str,
    state_dir: &Path,
    manifest_discovery: &ManifestDiscovery,
) -> Result<(), Error> {
    let definition = catalog
        .profile(profile_name)
        .ok_or_else(|| Error::NotInCatalog(profile_name.to_owned()))?;
    if let Err(err) = preflight_profile_manifest(manifest_discovery, definition) {
        let _ = write_stale_marker(state_dir, profile_name, &err.to_string());
        return Err(err);
    }
    let mut pulled = pull_profile_entries(secrets, definition)?;
    if let (Some(s3), Some(prefix)) = (s3, s3_prefix) {
        for doc in pull_profile_documents(s3, prefix, definition)? {
            pulled.push(PulledEntry {
                name: doc.slot_name,
                kind: Kind::File,
                bytes: doc.bytes,
            });
        }
    }
    if pulled.is_empty() {
        return Err(Error::EmptyBundle);
    }
    let seal_entries = seal_entries_from_pulled(&pulled);
    let lease = table
        .acquire_sync(SYNC_SLOT_INDEX, SYNC_ACQUIRE_TIMEOUT)
        .map_err(map_slot_acquire)?;
    let seal_result = (|| {
        let slot = table
            .slot_ref_mut(SYNC_SLOT_INDEX)
            .map_err(map_slot_acquire)?;
        let bundle = seal_profile_in_slot(catalog, slot, lease, profile_name, &seal_entries, kek)?;
        write_bundle_atomically(&bundle_path(state_dir, profile_name), &bundle)?;
        tracing::info!(
            target: "host_env_vault::application::sync",
            profile = profile_name,
            bytes = bundle.len(),
            "sync profile sealed replacing bundle"
        );
        clear_stale_marker(state_dir, profile_name)?;
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

/// Load every catalog-listed secret entry for one profile (no sealing).
pub(crate) fn pull_profile_entry_count(
    secrets: &dyn SecretSource,
    definition: &ProfileDefinition,
) -> Result<usize, Error> {
    pull_profile_entries(secrets, definition).map(|entries| entries.len())
}

fn pull_profile_entries(
    secrets: &dyn SecretSource,
    definition: &ProfileDefinition,
) -> Result<Vec<PulledEntry>, Error> {
    let mut entries = Vec::new();
    for name in definition.inject_env() {
        entries.push(fetch_pulled_entry(
            secrets,
            &definition.name,
            name,
            Kind::Env,
        )?);
    }
    for name in definition.runtime_env() {
        entries.push(fetch_pulled_entry(
            secrets,
            &definition.name,
            name,
            Kind::Env,
        )?);
    }
    for name in definition.inject_files() {
        entries.push(fetch_pulled_entry(
            secrets,
            &definition.name,
            name,
            Kind::File,
        )?);
    }
    for name in definition.runtime_files() {
        entries.push(fetch_pulled_entry(
            secrets,
            &definition.name,
            name,
            Kind::File,
        )?);
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
    secrets: &dyn SecretSource,
    profile_name: &str,
    entry_name: &str,
    kind: Kind,
) -> Result<PulledEntry, Error> {
    let text = secrets.load_entry(profile_name, entry_name)?;
    let bytes = text.into_bytes();
    let max = match kind {
        Kind::Env => SECRET_MAX_BYTES,
        Kind::File => SECRET_MAX_BYTES,
    };
    if bytes.len() > max {
        tracing::info!(
            target: "host_env_vault::application::sync",
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

pub(crate) fn write_bundle_atomically(path: &Path, bytes: &[u8]) -> Result<(), Error> {
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
    secrets: &dyn SecretSource,
    state_dir: &Path,
) -> Result<Catalog, Error> {
    let text = secrets.load_catalog()?;
    write_catalog_snapshot(state_dir, &text)?;
    parse_catalog_text(&text)
}

fn map_slot_acquire(err: crate::core::slot::SlotError) -> Error {
    Error::CatalogParse(format!("sync slot acquire: {err:?}"))
}

/// Test hook: parse catalog text without SSM.
pub fn sync_catalog_from_text(
    text: &str,
    secrets_prefix: &str,
    ssm: &dyn SsmPort,
    s3: Option<&dyn S3Port>,
    s3_prefix: Option<&str>,
    kek: &AgeKek,
    table: &mut SlotTable,
    state_dir: &Path,
) -> Result<(), Error> {
    std::fs::create_dir_all(state_dir)?;
    write_catalog_snapshot(state_dir, text)?;
    let catalog = parse_catalog_text(text)?;
    let manifest_dir = crate::application::manifest::default_manifests_dir(state_dir);
    for name in catalog.profile_names() {
        if let Some(definition) = catalog.profile(name) {
            crate::application::manifest::write_manifest_for_profile(&manifest_dir, definition)?;
        }
    }
    let mut names: Vec<_> = catalog.profile_names().collect();
    names.sort_unstable();
    let mut failures = 0usize;
    let secrets = SsmSecretSource::new(
        DEFAULT_CATALOG_PARAMETER,
        secrets_prefix,
        ssm,
    );
    let manifest_discovery = ManifestDiscovery::new(
        SyncSourceKind::Ssm,
        state_dir,
        None,
        None,
    );
    for profile_name in names {
        if sync_one_profile(
            &secrets,
            s3,
            s3_prefix,
            kek,
            table,
            &catalog,
            profile_name,
            state_dir,
            &manifest_discovery,
        )
        .is_err()
        {
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
mod host_store_integration_tests;

#[cfg(test)]
mod local_integration_tests;

#[cfg(test)]
mod log_tests;

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn bundle_and_ssm_paths_follow_plan_layout() {
        assert_eq!(
            bundle_path(Path::new("/var/lib/host-env-vault"), "app-web"),
            PathBuf::from("/var/lib/host-env-vault/app-web.hev")
        );
        assert_eq!(
            ssm_entry_parameter(DEFAULT_SECRETS_PREFIX, "app-web", "DB_PASS"),
            "/host-env-vault/app-web/DB_PASS"
        );
    }

    #[test]
    fn sync_slot_index_is_first_worker_slot() {
        assert_eq!(SYNC_SLOT_INDEX, 0);
        assert!(SYNC_SLOT_INDEX < crate::core::slot::SLOT_COUNT);
    }

    #[test]
    fn sync_options_stores_s3_prefix() {
        let options =
            SyncOptions::with_defaults(PathBuf::from("/etc/kek.age")).with_s3_prefix("recovery");
        assert_eq!(options.s3_prefix.as_deref(), Some("recovery"));
    }
}
