//! Host profile vault for Denarius and the Amtgard IDP.
//!
//! A profile is a process personality. `render` writes that profile's files to
//! an empty directory. `serve` holds the data key only for profiles marked
//! `runtime_key_wrap`, and the unix socket path is the profile name. Frames
//! carry 32-byte keys. They cannot name another profile or fetch an env secret.

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
pub mod serve;
pub mod slot;
pub mod sync;

pub use bundle::{open, open_bytes, seal, seal_bytes, Entry, Opened};
pub use local_bundle::{open_profile_into_slot, seal_profile_in_slot};
pub use catalog::{
    bind_catalog_profile, load_catalog_from_ssm, parse_catalog_text, validate_seal_entries,
    validate_serve_entry, Catalog, ProfileDefinition, SealEntry, DEFAULT_CATALOG_PARAMETER,
};
pub use error::Error;
pub use kek::AgeKek;
pub use port::{MemorySsm, SsmPort};
pub use profile::{Kind, ProfileId};
pub use render::{read_staging, render, RenderMode};
pub use serve::{dispatch, load_runtime_keys, RuntimeKeys};
pub use sync::{
    bundle_path, load_or_create_identity, ssm_entry_parameter, sync_from_ssm, SyncOptions,
    DEFAULT_STATE_DIR, SYNC_SLOT_INDEX,
};
