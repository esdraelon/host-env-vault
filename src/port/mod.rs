//! **Port** adapters for external systems. Commands depend on traits here.

pub mod s3;
pub mod ssm;

pub use s3::{MemoryS3, S3Error, S3Port};
pub use ssm::{MemorySsm, SsmError, SsmPort};
