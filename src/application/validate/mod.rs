//! **Validate command** — read-only dry-run: load catalog and every secret entry without sealing.

use std::path::PathBuf;

use crate::application::documents::pull_profile_documents;
use crate::application::manifest::{ManifestDiscovery, preflight_profile_manifest};
use crate::application::sync::pull_profile_entry_count;
use crate::catalog::{parse_catalog_text, Catalog, ProfileDefinition};
use crate::config::SyncSourceKind;
use crate::core::error::Error;
use crate::ports::s3::S3Port;
use crate::ports::secret_source::{LocalSecretSource, SecretSource, SsmSecretSource};
use crate::ports::ssm::SsmPort;

/// Parameter names and optional filters for a validate run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateOptions {
    pub catalog_param: String,
    pub secrets_prefix: String,
    pub state_dir: PathBuf,
    pub source: SyncSourceKind,
    pub local_secrets_dir: Option<PathBuf>,
    pub manifests_dir: Option<PathBuf>,
    pub s3_prefix: Option<String>,
    /// When set, only this catalog profile is checked.
    pub profile: Option<String>,
    /// Single-profile override path (requires [`ValidateOptions::profile`]).
    pub manifest_override: Option<PathBuf>,
}

impl ValidateOptions {
    pub fn new(catalog_param: String, secrets_prefix: String) -> Self {
        Self {
            catalog_param,
            secrets_prefix,
            state_dir: PathBuf::from(crate::application::sync::DEFAULT_STATE_DIR),
            source: SyncSourceKind::Ssm,
            local_secrets_dir: None,
            manifests_dir: None,
            s3_prefix: None,
            profile: None,
            manifest_override: None,
        }
    }

    pub fn with_s3_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.s3_prefix = Some(prefix.into());
        self
    }

    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    pub fn with_manifest_lookup(
        mut self,
        state_dir: PathBuf,
        source: SyncSourceKind,
        local_secrets_dir: Option<PathBuf>,
        manifests_dir: Option<PathBuf>,
    ) -> Self {
        self.state_dir = state_dir;
        self.source = source;
        self.local_secrets_dir = local_secrets_dir;
        self.manifests_dir = manifests_dir;
        self
    }

    pub fn with_manifest_override(mut self, path: PathBuf) -> Self {
        self.manifest_override = Some(path);
        self
    }

    fn manifest_discovery(&self) -> ManifestDiscovery {
        let mut discovery = ManifestDiscovery::new(
            self.source,
            &self.state_dir,
            self.local_secrets_dir.clone(),
            self.manifests_dir.clone(),
        );
        if let Some(path) = &self.manifest_override {
            discovery = discovery.with_override(path.clone());
        }
        discovery
    }
}

/// Validate secrets reachable via SSM (read-only).
pub fn validate_from_ssm(ssm: &dyn SsmPort, options: &ValidateOptions) -> Result<(), Error> {
    let secrets = SsmSecretSource::new(
        &options.catalog_param,
        &options.secrets_prefix,
        ssm,
    );
    validate_from_secret_source(&secrets, None, options)
}

/// Validate secrets from a local dev directory (read-only).
pub fn validate_from_local(
    local_secrets_dir: &std::path::Path,
    s3: Option<&dyn S3Port>,
    options: &ValidateOptions,
) -> Result<(), Error> {
    let secrets = LocalSecretSource::new(local_secrets_dir);
    validate_from_secret_source(&secrets, s3, options)
}

/// Validate catalog and entries from any [`SecretSource`].
pub fn validate_from_secret_source(
    secrets: &dyn SecretSource,
    s3: Option<&dyn S3Port>,
    options: &ValidateOptions,
) -> Result<(), Error> {
    if options.manifest_override.is_some() && options.profile.is_none() {
        return Err(Error::CatalogParse(
            "validate --manifest requires --profile (per-profile discovery is the default)".into(),
        ));
    }
    let catalog = load_catalog_read_only(secrets)?;
    tracing::info!(
        target: "host_env_vault::application::validate",
        profile_count = catalog.profile_names().count(),
        "validate catalog loaded"
    );
    let discovery = options.manifest_discovery();
    let mut names: Vec<_> = catalog.profile_names().collect();
    names.sort_unstable();
    if let Some(filter) = &options.profile {
        names.retain(|name| *name == filter.as_str());
        if names.is_empty() {
            return Err(Error::NotInCatalog(filter.clone()));
        }
    }
    let mut failures = 0usize;
    for profile_name in names {
        let definition = catalog
            .profile(profile_name)
            .ok_or_else(|| Error::NotInCatalog(profile_name.to_owned()))?;
        if let Err(err) = preflight_profile_manifest(&discovery, definition) {
            failures += 1;
            tracing::info!(
                target: "host_env_vault::application::validate",
                profile = profile_name,
                error = %err,
                "validate profile failed manifest preflight"
            );
            eprintln!("validate: profile {profile_name}: {err}");
            continue;
        }
        match validate_one_profile(secrets, s3, options.s3_prefix.as_deref(), definition) {
            Ok(entry_count) => {
                tracing::info!(
                    target: "host_env_vault::application::validate",
                    profile = profile_name,
                    entries = entry_count,
                    "validate profile ok"
                );
                println!("validate: profile {profile_name} ok ({entry_count} entries)");
            }
            Err(err) => {
                failures += 1;
                tracing::info!(
                    target: "host_env_vault::application::validate",
                    profile = profile_name,
                    error = %err,
                    "validate profile failed"
                );
                eprintln!("validate: profile {profile_name}: {err}");
            }
        }
    }
    if failures > 0 {
        return Err(Error::ValidateFailed { count: failures });
    }
    Ok(())
}

fn load_catalog_read_only(secrets: &dyn SecretSource) -> Result<Catalog, Error> {
    let text = secrets.load_catalog()?;
    parse_catalog_text(&text)
}

fn validate_one_profile(
    secrets: &dyn SecretSource,
    s3: Option<&dyn S3Port>,
    s3_prefix: Option<&str>,
    definition: &ProfileDefinition,
) -> Result<usize, Error> {
    let mut count = pull_profile_entry_count(secrets, definition)?;
    if let (Some(s3), Some(prefix)) = (s3, s3_prefix) {
        let docs = pull_profile_documents(s3, prefix, definition)?;
        count += docs.len();
    }
    Ok(count)
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod log_tests;
