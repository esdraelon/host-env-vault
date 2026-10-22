//! Hexagonal ports for SSM, S3, and `gh`.

pub mod gh;
pub mod secret_source;
pub mod s3;
pub mod ssm;

pub use gh::{GhError, GhPort, MemoryGh};
pub use secret_source::{
    local_file_entry_path, local_profile_env_basename, HostStoreSecretSource, LocalSecretSource,
    SecretSource, SsmSecretSource, LOCAL_CATALOG_FILE, ssm_entry_parameter,
};
pub use s3::{MemoryS3, S3Error, S3Port};
pub use ssm::{MemorySsm, SsmError, SsmPort};
