//! Host-side profile vault: sync secrets from AWS, seal locally, render or serve per profile.
//!
//! Layout:
//! - [`core`] — errors and fixed-capacity slots
//! - [`vault`] — age KEK and HEV1 bundles
//! - [`catalog`] — profile definitions from SSM
//! - [`ports`] — SSM, S3, and `gh` traits
//! - [`application`] — sync, render, serve, documents, hydrate
//! - [`legacy`] — spike enum profiles and staging helpers
//!
//! Root re-exports keep the public API stable for callers and tests.

#[cfg(not(unix))]
compile_error!("host-env-vault is a unix host agent");

pub mod application;
pub mod catalog;
pub mod config;
pub mod core;
pub mod legacy;
pub mod ports;
pub mod vault;

#[cfg(test)]
mod testing;

// Stable names used across the repo and in `main`.
pub use application::documents::{
    document_slot_name, is_secret_shaped_s3_key, load_documents_into_slot, pull_profile_documents,
    seal_entries_from_documents, PulledDocument,
};
pub use application::fetch_documents::{fetch_profile_documents, FetchDocumentsOptions};
pub use application::hydrate::{
    hydrate_gh_from_vault, hydrate_gh_with_catalog, HydrateGhOptions, GITHUB_PROFILE,
    HYDRATE_SLOT_INDEX,
};
pub use application::render::{
    render_from_vault, render_profile_with_catalog, RenderOptions, RENDER_SLOT_INDEX,
};
pub use application::serve::{
    bind_serve_socket, fetch_runtime_entry, serve_profile_forever, ServeOptions, SERVE_SLOT_INDEX,
};
pub use application::sync::{
    bundle_path, load_or_create_identity, ssm_entry_parameter,
    sync_catalog_from_text, sync_from_local, sync_from_ports, sync_from_secret_source,
    sync_from_ssm, SyncOptions, DEFAULT_STATE_DIR, SYNC_SLOT_INDEX,
};
pub use application::validate::{
    validate_from_local, validate_from_secret_source, validate_from_ssm, ValidateOptions,
};
pub use config::{
    load_config, parse_config_text, parse_sync_source, resolve_config_path, FileConfig,
    RenderCliOverrides, ResolvedSync, ResolvedValidate, ServeCliOverrides, SyncCliOverrides,
    SyncSourceKind, ValidateCliOverrides,
    CONFIG_ENV_VAR, DEFAULT_CONFIG_PATH, DEFAULT_RUNTIME_DIR,
};
pub use catalog::{
    bind_catalog_profile, catalog_snapshot_path, load_catalog_from_ssm, load_catalog_snapshot,
    parse_catalog_text, validate_seal_entries, validate_serve_entry, write_catalog_snapshot,
    Catalog, ProfileDefinition, SealEntry, CATALOG_SNAPSHOT_FILE, DEFAULT_CATALOG_PARAMETER,
    DEFAULT_SECRETS_PREFIX,
};
pub use core::error::Error;
pub use core::slot;
pub use core::slot::SlotTable;
pub use legacy::profile::{Kind, ProfileId};
pub use legacy::render::{read_staging, render, RenderMode};
pub use ports::{
    GhError, GhPort, LocalSecretSource, MemoryGh, MemoryS3, MemorySsm, S3Port, SecretSource,
    SsmPort, SsmSecretSource, LOCAL_CATALOG_FILE,
};
pub use vault::bundle::{open, open_bytes, seal, seal_bytes, Entry, Opened};
pub use vault::kek::AgeKek;
pub use vault::local_bundle::{open_profile_into_slot, seal_profile_in_slot};

/// Same module path as before the layout split (`host_env_vault::port`).
pub use ports as port;
