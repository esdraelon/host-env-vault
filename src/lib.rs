//! Host profile vault for Denarius and the Amtgard IDP.
//!
//! A profile is a process personality. `render` writes that profile's files to
//! an empty directory. `serve` exposes runtime-listed entries on a per-profile
//! unix socket; the path is the profile name and each frame names one entry.

#[cfg(not(unix))]
compile_error!("host-env-vault is a unix host agent");

pub mod bundle;
pub mod catalog;
pub mod documents;
pub mod local_bundle;
pub mod error;
pub mod fetch_documents_cmd;
pub mod hydrate_cmd;
pub mod kek;
pub mod port;
pub mod profile;
pub mod render;
pub mod render_cmd;
pub mod serve;
pub mod serve_cmd;
pub mod slot;
pub mod sync;

#[cfg(test)]
mod log_test_capture;

#[cfg(test)]
mod mutation_closeout;

pub use bundle::{open, open_bytes, seal, seal_bytes, Entry, Opened};
pub use local_bundle::{open_profile_into_slot, seal_profile_in_slot};
pub use catalog::{
    bind_catalog_profile, catalog_snapshot_path, load_catalog_from_ssm, load_catalog_snapshot,
    parse_catalog_text, validate_seal_entries, validate_serve_entry, write_catalog_snapshot,
    Catalog, ProfileDefinition, SealEntry, CATALOG_SNAPSHOT_FILE, DEFAULT_CATALOG_PARAMETER,
};
pub use error::Error;
pub use kek::AgeKek;
pub use documents::{
    document_slot_name, is_secret_shaped_s3_key, load_documents_into_slot, pull_profile_documents,
    seal_entries_from_documents, PulledDocument,
};
pub use hydrate_cmd::{
    hydrate_gh_from_vault, hydrate_gh_with_catalog, HydrateGhOptions, GITHUB_PROFILE,
    HYDRATE_SLOT_INDEX,
};
pub use port::{GhError, GhPort, MemoryGh, MemoryS3, MemorySsm, S3Port, SsmPort};
pub use profile::{Kind, ProfileId};
pub use render::{read_staging, render, RenderMode};
pub use render_cmd::{
    render_from_vault, render_profile_with_catalog, RenderOptions, RENDER_SLOT_INDEX,
};
pub use serve_cmd::{
    bind_serve_socket, fetch_runtime_entry, serve_profile_forever, ServeOptions, SERVE_SLOT_INDEX,
};
pub use fetch_documents_cmd::{fetch_profile_documents, FetchDocumentsOptions};
pub use sync::{
    bundle_path, load_or_create_identity, ssm_entry_parameter, sync_from_ports, sync_from_ssm,
    SyncOptions, DEFAULT_STATE_DIR, SYNC_SLOT_INDEX,
};
