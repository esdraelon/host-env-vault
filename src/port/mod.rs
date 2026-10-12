//! **Port** adapters for external systems. Commands depend on traits here.

pub mod ssm;

pub use ssm::{MemorySsm, SsmError, SsmPort};
