//! TOML configuration: file defaults with CLI overrides.

use std::env;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tracing::debug;

use crate::application::sync::DEFAULT_STATE_DIR;
use crate::catalog::{DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};
use crate::Error;

/// Default path when `HOST_ENV_VAULT_CONFIG` is unset.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/host-env-vault/config.toml";

/// Environment variable for the config file path.
pub const CONFIG_ENV_VAR: &str = "HOST_ENV_VAULT_CONFIG";

/// Default runtime directory for `serve`.
pub const DEFAULT_RUNTIME_DIR: &str = "/run/host-env-vault";

/// On-disk TOML shape (all fields optional).
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
pub struct FileConfig {
    pub identity: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub runtime_dir: Option<PathBuf>,
    #[serde(default)]
    pub sync: SyncFileSection,
}

/// `[sync]` table.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SyncFileSection {
    pub source: Option<String>,
    pub catalog_param: Option<String>,
    pub secrets_prefix: Option<String>,
    pub local_secrets_dir: Option<PathBuf>,
    pub s3_bucket: Option<String>,
    pub s3_prefix: Option<String>,
}

/// Resolved sync settings after merge (file then CLI over hardcoded defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSync {
    pub identity: PathBuf,
    pub state_dir: PathBuf,
    pub source: SyncSourceKind,
    pub catalog_param: String,
    pub secrets_prefix: String,
    pub local_secrets_dir: Option<PathBuf>,
    pub s3_bucket: Option<String>,
    pub s3_prefix: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncSourceKind {
    Ssm,
    Local,
}

/// CLI-only overrides for `sync` (set flags win over file and defaults).
#[derive(Debug, Default)]
pub struct SyncCliOverrides {
    pub identity: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub source: Option<SyncSourceKind>,
    pub catalog_param: Option<String>,
    pub secrets_prefix: Option<String>,
    pub local_secrets_dir: Option<PathBuf>,
    pub s3_bucket: Option<String>,
    pub s3_prefix: Option<String>,
}

#[derive(Debug, Default)]
pub struct RenderCliOverrides {
    pub identity: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct ServeCliOverrides {
    pub identity: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub runtime_dir: Option<PathBuf>,
}

/// Path from `--config`, then `HOST_ENV_VAULT_CONFIG`, then [`DEFAULT_CONFIG_PATH`].
pub fn resolve_config_path(cli_path: Option<PathBuf>) -> PathBuf {
    if let Some(path) = cli_path {
        return path;
    }
    env::var(CONFIG_ENV_VAR)
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

/// Load config from disk. A missing file yields an empty config (defaults only).
pub fn load_config(path: &Path) -> Result<FileConfig, Error> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            debug!(path = %path.display(), "loaded host-env-vault config");
            parse_config_text(&text)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            debug!(path = %path.display(), "config file absent, using defaults");
            Ok(FileConfig::default())
        }
        Err(err) => Err(err.into()),
    }
}

/// Parse TOML text (tests and load).
pub fn parse_config_text(text: &str) -> Result<FileConfig, Error> {
    toml::from_str(text).map_err(|err| Error::CatalogParse(format!("config parse: {err}")))
}

impl FileConfig {
    pub fn resolve_sync(&self, cli: &SyncCliOverrides) -> Result<ResolvedSync, Error> {
        let identity = pick_path(
            cli.identity.as_ref(),
            self.identity.as_ref(),
            None,
            "identity (set in config or pass --identity)",
        )?;
        let state_dir = pick_path(
            cli.state_dir.as_ref(),
            self.state_dir.as_ref(),
            Some(DEFAULT_STATE_DIR),
            "state_dir",
        )?;
        let source = pick_source(cli.source, self.sync.source.as_deref())?;
        let catalog_param = pick_string(
            cli.catalog_param.as_deref(),
            self.sync.catalog_param.as_deref(),
            DEFAULT_CATALOG_PARAMETER,
        );
        let secrets_prefix = pick_string(
            cli.secrets_prefix.as_deref(),
            self.sync.secrets_prefix.as_deref(),
            DEFAULT_SECRETS_PREFIX,
        );
        let local_secrets_dir = cli
            .local_secrets_dir
            .clone()
            .or_else(|| self.sync.local_secrets_dir.clone());
        let s3_bucket = cli
            .s3_bucket
            .clone()
            .or_else(|| self.sync.s3_bucket.clone());
        let s3_prefix = cli
            .s3_prefix
            .clone()
            .or_else(|| self.sync.s3_prefix.clone());

        Ok(ResolvedSync {
            identity,
            state_dir,
            source,
            catalog_param,
            secrets_prefix,
            local_secrets_dir,
            s3_bucket,
            s3_prefix,
        })
    }

    pub fn resolve_render(&self, cli: &RenderCliOverrides) -> Result<(PathBuf, PathBuf), Error> {
        let identity = pick_path(
            cli.identity.as_ref(),
            self.identity.as_ref(),
            None,
            "identity (set in config or pass --identity)",
        )?;
        let state_dir = pick_path(
            cli.state_dir.as_ref(),
            self.state_dir.as_ref(),
            Some(DEFAULT_STATE_DIR),
            "state_dir",
        )?;
        Ok((identity, state_dir))
    }

    pub fn resolve_serve(
        &self,
        cli: &ServeCliOverrides,
    ) -> Result<(PathBuf, PathBuf, PathBuf), Error> {
        let identity = pick_path(
            cli.identity.as_ref(),
            self.identity.as_ref(),
            None,
            "identity (set in config or pass --identity)",
        )?;
        let state_dir = pick_path(
            cli.state_dir.as_ref(),
            self.state_dir.as_ref(),
            Some(DEFAULT_STATE_DIR),
            "state_dir",
        )?;
        let runtime_dir = pick_path(
            cli.runtime_dir.as_ref(),
            self.runtime_dir.as_ref(),
            Some(DEFAULT_RUNTIME_DIR),
            "runtime_dir (set in config or pass --runtime-dir)",
        )?;
        Ok((identity, state_dir, runtime_dir))
    }
}

fn pick_path(
    cli: Option<&PathBuf>,
    file: Option<&PathBuf>,
    default: Option<&str>,
    label: &str,
) -> Result<PathBuf, Error> {
    if let Some(p) = cli {
        return Ok(p.clone());
    }
    if let Some(p) = file {
        return Ok(p.clone());
    }
    if let Some(d) = default {
        return Ok(PathBuf::from(d));
    }
    Err(Error::CatalogParse(format!("missing {label}")))
}

fn pick_string(cli: Option<&str>, file: Option<&str>, default: &str) -> String {
    cli.map(str::to_owned)
        .or_else(|| file.map(str::to_owned))
        .unwrap_or_else(|| default.to_owned())
}

fn pick_source(
    cli: Option<SyncSourceKind>,
    file: Option<&str>,
) -> Result<SyncSourceKind, Error> {
    if let Some(s) = cli {
        return Ok(s);
    }
    if let Some(text) = file {
        return parse_sync_source(text);
    }
    Ok(SyncSourceKind::Ssm)
}

pub fn parse_sync_source(text: &str) -> Result<SyncSourceKind, Error> {
    match text.trim().to_ascii_lowercase().as_str() {
        "ssm" => Ok(SyncSourceKind::Ssm),
        "local" => Ok(SyncSourceKind::Local),
        other => Err(Error::CatalogParse(format!(
            "invalid sync source `{other}` (expected ssm or local)"
        ))),
    }
}

#[cfg(test)]
mod behavior_tests;
