//! **Catalog port** — SSM-backed profile allowlists. The binary has no
//! application enum; profile names and entry lists come from JSON or TOML.

mod guard;
mod load;
mod parse;

pub use guard::{validate_seal_entries, validate_serve_entry, SealEntry};
pub use load::{bind_catalog_profile, load_catalog_from_ssm};
pub use parse::{parse_catalog_text, Catalog, ProfileDefinition};

pub const DEFAULT_CATALOG_PARAMETER: &str = "/amtgard/vault/profiles";

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod log_tests;

#[cfg(test)]
mod parse_tests;
