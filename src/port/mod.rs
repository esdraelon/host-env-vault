//! **Port** adapters for external systems. Commands depend on traits here.

pub mod gh;
pub mod s3;
pub mod ssm;

pub use gh::{GhError, GhPort, MemoryGh};
pub use s3::{MemoryS3, S3Error, S3Port};
pub use ssm::{MemorySsm, SsmError, SsmPort};
