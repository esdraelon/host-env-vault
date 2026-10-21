//! Per-profile `{profile}.env-host-vault` manifests: discovery, load, strict catalog cross-check.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::catalog::ProfileDefinition;
use crate::config::SyncSourceKind;
use crate::core::error::Error;

/// Synthetic inject env line added at render time when a profile bundle is stale.
pub const ENV_HOST_VAULT_STALE: &str = "ENV_HOST_VAULT_STALE";

const MANIFEST_SUFFIX: &str = ".env-host-vault";

/// Default directory for profile manifests when using SSM (under host state).
pub fn default_manifests_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("manifests")
}

/// Path to the stale marker for one profile after a failed sync preflight.
pub fn stale_marker_path(state_dir: &Path, profile_name: &str) -> PathBuf {
    state_dir.join(format!("{profile_name}.stale"))
}

/// Where discovery looks for manifests before sync/validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDiscovery {
    pub source: SyncSourceKind,
    pub local_secrets_dir: Option<PathBuf>,
    pub manifests_dir: PathBuf,
    /// Validate-only: when set with a single `--profile`, load this file instead of discovery.
    pub override_path: Option<PathBuf>,
}

impl ManifestDiscovery {
    pub fn new(
        source: SyncSourceKind,
        state_dir: &Path,
        local_secrets_dir: Option<PathBuf>,
        manifests_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            source,
            local_secrets_dir,
            manifests_dir: manifests_dir
                .unwrap_or_else(|| default_manifests_dir(state_dir)),
            override_path: None,
        }
    }

    pub fn with_override(mut self, path: PathBuf) -> Self {
        self.override_path = Some(path);
        self
    }

    /// Resolved path for one profile (does not check existence).
    pub fn resolve_path(&self, profile_name: &str) -> PathBuf {
        if let Some(path) = &self.override_path {
            return path.clone();
        }
        if self.source == SyncSourceKind::Local {
            if let Some(dir) = &self.local_secrets_dir {
                let local = dir.join(manifest_file_name(profile_name));
                if local.is_file() {
                    return local;
                }
            }
        }
        self.manifests_dir.join(manifest_file_name(profile_name))
    }
}

fn manifest_file_name(profile_name: &str) -> String {
    format!("{profile_name}{MANIFEST_SUFFIX}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileManifest {
    pub profile: String,
    pub inject_env: Vec<String>,
    pub inject_files: Vec<String>,
    pub runtime_env: Vec<String>,
    pub runtime_files: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ProfileManifestFile {
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

/// Load manifest from disk (caller supplies resolved path).
pub fn load_profile_manifest(path: &Path) -> Result<ProfileManifest, Error> {
    let text = std::fs::read_to_string(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            Error::ManifestMissing {
                profile: profile_from_manifest_path(path),
                path: path.to_path_buf(),
            }
        } else {
            Error::Io(err)
        }
    })?;
    parse_manifest_text(&text)
}

fn profile_from_manifest_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(MANIFEST_SUFFIX))
        .unwrap_or("unknown")
        .to_owned()
}

fn parse_manifest_text(text: &str) -> Result<ProfileManifest, Error> {
    let raw: ProfileManifestFile = toml::from_str(text)
        .map_err(|err| Error::CatalogParse(format!("manifest parse: {err}")))?;
    Ok(ProfileManifest {
        profile: raw.profile,
        inject_env: raw.inject.env,
        inject_files: raw.inject.files,
        runtime_env: raw.runtime.env,
        runtime_files: raw.runtime.files,
    })
}

/// Discover, load, and strictly cross-check manifest against catalog for one profile.
pub fn preflight_profile_manifest(
    discovery: &ManifestDiscovery,
    definition: &ProfileDefinition,
) -> Result<(), Error> {
    let path = discovery.resolve_path(&definition.name);
    let manifest = load_profile_manifest(&path)?;
    if manifest.profile != definition.name {
        return Err(Error::ManifestMismatch {
            profile: definition.name.clone(),
            detail: format!(
                "manifest profile `{}` does not match catalog profile `{}`",
                manifest.profile, definition.name
            ),
        });
    }
    strict_cross_check(definition, &manifest)
}

pub fn strict_cross_check(
    definition: &ProfileDefinition,
    manifest: &ProfileManifest,
) -> Result<(), Error> {
    compare_list(
        &definition.name,
        "inject env",
        definition.inject_env(),
        &manifest.inject_env,
    )?;
    compare_list(
        &definition.name,
        "inject file",
        definition.inject_files(),
        &manifest.inject_files,
    )?;
    compare_list(
        &definition.name,
        "runtime env",
        definition.runtime_env(),
        &manifest.runtime_env,
    )?;
    compare_list(
        &definition.name,
        "runtime file",
        definition.runtime_files(),
        &manifest.runtime_files,
    )?;
    Ok(())
}

fn compare_list(
    profile: &str,
    label: &str,
    catalog: &[String],
    manifest: &[String],
) -> Result<(), Error> {
    let catalog_set: HashSet<&str> = catalog.iter().map(String::as_str).collect();
    let manifest_set: HashSet<&str> = manifest.iter().map(String::as_str).collect();
    if catalog_set == manifest_set {
        return Ok(());
    }
    let mut only_catalog: Vec<_> = catalog_set.difference(&manifest_set).copied().collect();
    only_catalog.sort_unstable();
    let mut only_manifest: Vec<_> = manifest_set.difference(&catalog_set).copied().collect();
    only_manifest.sort_unstable();
    let mut detail = format!("{label} mismatch");
    if !only_catalog.is_empty() {
        detail.push_str(&format!("; catalog only: {}", only_catalog.join(", ")));
    }
    if !only_manifest.is_empty() {
        detail.push_str(&format!("; manifest only: {}", only_manifest.join(", ")));
    }
    Err(Error::ManifestMismatch {
        profile: profile.to_owned(),
        detail,
    })
}

/// Record sync preflight failure so render can expose [`ENV_HOST_VAULT_STALE`].
pub fn write_stale_marker(state_dir: &Path, profile_name: &str, reason: &str) -> Result<(), Error> {
    let path = stale_marker_path(state_dir, profile_name);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&path, reason)?;
    tracing::info!(
        target: "host_env_vault::application::manifest",
        profile = profile_name,
        path = %path.display(),
        "sync preflight failed wrote stale marker"
    );
    Ok(())
}

/// Clear stale marker after a successful profile sync.
pub fn clear_stale_marker(state_dir: &Path, profile_name: &str) -> Result<(), Error> {
    let path = stale_marker_path(state_dir, profile_name);
    match std::fs::remove_file(&path) {
        Ok(()) => {
            tracing::info!(
                target: "host_env_vault::application::manifest",
                profile = profile_name,
                "sync success cleared stale marker"
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

pub fn profile_is_stale(state_dir: &Path, profile_name: &str) -> bool {
    stale_marker_path(state_dir, profile_name).is_file()
}

/// Write a manifest matching a catalog profile (tests and examples).
/// Write one `{profile}.env-host-vault` per catalog profile under the default manifests dir.
pub fn seed_manifests_for_catalog_text(state_dir: &Path, catalog_text: &str) -> Result<(), Error> {
    let catalog = crate::catalog::parse_catalog_text(catalog_text)?;
    let dir = default_manifests_dir(state_dir);
    for name in catalog.profile_names() {
        if let Some(definition) = catalog.profile(name) {
            write_manifest_for_profile(&dir, definition)?;
        }
    }
    Ok(())
}

pub fn write_manifest_for_profile(
    dir: &Path,
    definition: &ProfileDefinition,
) -> Result<PathBuf, Error> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(manifest_file_name(&definition.name));
    let body = format!(
        r#"profile = "{}"
[inject]
env = [{}]
files = [{}]
[runtime]
env = [{}]
files = [{}]
"#,
        definition.name,
        quote_list(definition.inject_env()),
        quote_list(definition.inject_files()),
        quote_list(definition.runtime_env()),
        quote_list(definition.runtime_files()),
    );
    std::fs::write(&path, body)?;
    Ok(path)
}

fn quote_list(names: &[String]) -> String {
    names
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod behavior_tests;
