//! Host profile vault for Denarius and the Amtgard IDP.
//!
//! A profile is a process personality. `render` writes that profile's files to
//! an empty directory. `serve` exposes runtime-listed entries on a per-profile
//! unix socket; the path is the profile name and each frame names one entry.

#[cfg(not(unix))]
compile_error!("host-env-vault is a unix host agent");

pub mod bundle;
pub mod catalog;
pub mod local_bundle;
pub mod error;
pub mod kek;
pub mod port;
pub mod profile;
pub mod render;
pub mod render_cmd;
pub mod serve;
pub mod serve_cmd;
pub mod slot;
pub mod sync;

pub use bundle::{open, open_bytes, seal, seal_bytes, Entry, Opened};
pub use local_bundle::{open_profile_into_slot, seal_profile_in_slot};
pub use catalog::{
    bind_catalog_profile, catalog_snapshot_path, load_catalog_from_ssm, load_catalog_snapshot,
    parse_catalog_text, validate_seal_entries, validate_serve_entry, write_catalog_snapshot,
    Catalog, ProfileDefinition, SealEntry, CATALOG_SNAPSHOT_FILE, DEFAULT_CATALOG_PARAMETER,
};
pub use error::Error;
pub use kek::AgeKek;
pub use port::{MemorySsm, SsmPort};
pub use profile::{Kind, ProfileId};
pub use render::{read_staging, render, RenderMode};
pub use render_cmd::{
    render_from_vault, render_profile_with_catalog, RenderOptions, RENDER_SLOT_INDEX,
};
pub use serve_cmd::{
    bind_serve_socket, fetch_runtime_entry, serve_profile_forever, ServeOptions, SERVE_SLOT_INDEX,
};
pub use sync::{
    bundle_path, load_or_create_identity, ssm_entry_parameter, sync_from_ssm, SyncOptions,
    DEFAULT_STATE_DIR, SYNC_SLOT_INDEX,
};
