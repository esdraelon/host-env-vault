//! Host profile vault for Denarius and the Amtgard IDP.
//!
//! A profile is a process personality. `render` writes that profile's files to
//! an empty directory. `serve` holds the data key only for profiles marked
//! `runtime_key_wrap`, and the unix socket path is the profile name. Frames
//! carry 32-byte keys. They cannot name another profile or fetch an env secret.

#[cfg(not(unix))]
compile_error!("host-env-vault is a unix host agent");

pub mod bundle;
pub mod error;
pub mod kek;
pub mod profile;
pub mod render;
pub mod serve;

pub use bundle::{open, seal, Entry, Opened};
pub use error::Error;
pub use kek::AgeKek;
pub use profile::{Kind, ProfileId};
pub use render::{read_staging, render, RenderMode};
pub use serve::{dispatch, load_runtime_keys, RuntimeKeys};
