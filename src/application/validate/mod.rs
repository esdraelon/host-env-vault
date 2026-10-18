//! **Validate command** — read-only dry-run: load catalog and every secret entry without sealing.

use std::path::PathBuf;

use crate::application::documents::pull_profile_documents;
use crate::application::sync::pull_profile_entry_count;
use crate::catalog::{parse_catalog_text, Catalog, ProfileDefinition};
use crate::core::error::Error;
use crate::ports::s3::S3Port;
use crate::ports::secret_source::{LocalSecretSource, SecretSource, SsmSecretSource};
use crate::ports::ssm::SsmPort;

/// Parameter names and optional filters for a validate run (no host identity or state dir).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateOptions {
    pub catalog_param: String,
    pub secrets_prefix: String,
    pub s3_prefix: Option<String>,
    /// When set, only this catalog profile is checked.
    pub profile: Option<String>,
    /// Optional per-app manifest for cross-checking expected entry names (see `docs/validate.md`).
    pub manifest_path: Option<PathBuf>,
}

impl ValidateOptions {
    pub fn new(catalog_param: String, secrets_prefix: String) -> Self {
        Self {
            catalog_param,
            secrets_prefix,
            s3_prefix: None,
            profile: None,
            manifest_path: None,
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

    pub fn with_manifest(mut self, path: PathBuf) -> Self {
        self.manifest_path = Some(path);
        self
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
    let catalog = load_catalog_read_only(secrets)?;
    tracing::info!(
        target: "host_env_vault::application::validate",
        profile_count = catalog.profile_names().count(),
        "validate catalog loaded"
    );
    let manifest = options
        .manifest_path
        .as_ref()
        .map(|path| load_manifest(path))
        .transpose()?;
    if let Some(manifest) = &manifest {
        if let Some(filter) = &options.profile {
            if manifest.profile != *filter {
                return Err(Error::CatalogParse(format!(
                    "manifest profile `{}` does not match --profile `{filter}`",
                    manifest.profile
                )));
            }
        }
    }
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
        if let Some(manifest) = &manifest {
            if manifest.profile != profile_name {
                continue;
            }
            if let Err(err) = cross_check_manifest(definition, manifest) {
                failures += 1;
                tracing::info!(
                    target: "host_env_vault::application::validate",
                    profile = profile_name,
                    error = %err,
                    "validate profile failed manifest cross-check"
                );
                eprintln!("validate: profile {profile_name}: {err}");
                continue;
            }
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppManifest {
    profile: String,
    inject_env: Vec<String>,
    inject_files: Vec<String>,
    runtime_env: Vec<String>,
    runtime_files: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct AppManifestFile {
    profile: String,
    #[serde(default)]
    inject: ManifestSection,
    #[serde(default)]
    runtime: ManifestSection,
}

#[derive(Debug, Default, serde::Deserialize)]
struct ManifestSection {
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    files: Vec<String>,
}

fn load_manifest(path: &std::path::Path) -> Result<AppManifest, Error> {
    let text = std::fs::read_to_string(path).map_err(Error::Io)?;
    let raw: AppManifestFile = toml::from_str(&text)
        .map_err(|err| Error::CatalogParse(format!("manifest parse: {err}")))?;
    Ok(AppManifest {
        profile: raw.profile,
        inject_env: raw.inject.env,
        inject_files: raw.inject.files,
        runtime_env: raw.runtime.env,
        runtime_files: raw.runtime.files,
    })
}

fn cross_check_manifest(definition: &ProfileDefinition, manifest: &AppManifest) -> Result<(), Error> {
    reject_manifest_unknown(
        definition,
        &manifest.inject_env,
        definition.inject_env(),
        "inject env",
    )?;
    reject_manifest_unknown(
        definition,
        &manifest.inject_files,
        definition.inject_files(),
        "inject file",
    )?;
    reject_manifest_unknown(
        definition,
        &manifest.runtime_env,
        definition.runtime_env(),
        "runtime env",
    )?;
    reject_manifest_unknown(
        definition,
        &manifest.runtime_files,
        definition.runtime_files(),
        "runtime file",
    )?;
    warn_catalog_not_in_manifest(definition.name.as_str(), "inject env", definition.inject_env(), &manifest.inject_env);
    warn_catalog_not_in_manifest(
        definition.name.as_str(),
        "inject file",
        definition.inject_files(),
        &manifest.inject_files,
    );
    warn_catalog_not_in_manifest(
        definition.name.as_str(),
        "runtime env",
        definition.runtime_env(),
        &manifest.runtime_env,
    );
    warn_catalog_not_in_manifest(
        definition.name.as_str(),
        "runtime file",
        definition.runtime_files(),
        &manifest.runtime_files,
    );
    Ok(())
}

fn reject_manifest_unknown(
    definition: &ProfileDefinition,
    manifest_names: &[String],
    catalog_names: &[String],
    kind: &'static str,
) -> Result<(), Error> {
    let allowed: std::collections::HashSet<&str> = catalog_names.iter().map(String::as_str).collect();
    for name in manifest_names {
        if !allowed.contains(name.as_str()) {
            return Err(Error::EntryNotAllowed {
                name: name.clone(),
                kind,
                profile: definition.name.clone(),
            });
        }
    }
    Ok(())
}

fn warn_catalog_not_in_manifest(
    profile: &str,
    label: &str,
    catalog_names: &[String],
    manifest_names: &[String],
) {
    let listed: std::collections::HashSet<&str> = manifest_names.iter().map(String::as_str).collect();
    for name in catalog_names {
        if !listed.contains(name.as_str()) {
            tracing::warn!(
                target: "host_env_vault::application::validate",
                profile,
                entry = name.as_str(),
                kind = label,
                "validate manifest omits catalog entry"
            );
        }
    }
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod log_tests;
