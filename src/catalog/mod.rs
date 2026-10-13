//! **Catalog port** — SSM-backed profile allowlists. The binary has no
//! application enum; profile names and entry lists come from JSON or TOML.

mod guard;
mod load;
mod local;
mod parse;

pub use guard::{validate_seal_entries, validate_serve_entry, SealEntry};
pub use load::{bind_catalog_profile, load_catalog_from_ssm};
pub use local::{
    catalog_snapshot_path, load_catalog_snapshot, write_catalog_snapshot, CATALOG_SNAPSHOT_FILE,
};
pub use parse::{parse_catalog_text, Catalog, ProfileDefinition};

/// SSM parameter holding the profile catalog JSON (`SecureString`).
pub const DEFAULT_CATALOG_PARAMETER: &str = "/host-env-vault/profiles";

/// Prefix for per-entry SSM parameters: `{prefix}/{profile}/{entry}`.
pub const DEFAULT_SECRETS_PREFIX: &str = "/host-env-vault";

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod log_tests;

#[cfg(test)]
mod parse_tests;
