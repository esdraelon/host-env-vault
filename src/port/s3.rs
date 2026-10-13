//! **Hexagonal port** for S3 object reads. Production uses the SDK;
//! tests inject [`MemoryS3`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Failures fetching an object. Messages never include object bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum S3Error {
    #[error("object `{0}` not found")]
    NotFound(String),
    #[error("object store unavailable")]
    Unavailable,
}

/// Read-only S3 access for plain recovery documents.
pub trait S3Port {
    fn get_object(&self, key: &str) -> Result<Vec<u8>, S3Error>;
}

/// In-memory object map for unit tests and integration stubs.
#[derive(Debug, Default, Clone)]
pub struct MemoryS3 {
    inner: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MemoryS3 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&self, key: impl Into<String>, value: impl AsRef<[u8]>) {
        self.inner
            .lock()
            .expect("memory s3 lock")
            .insert(key.into(), value.as_ref().to_vec());
    }
}

impl S3Port for MemoryS3 {
    fn get_object(&self, key: &str) -> Result<Vec<u8>, S3Error> {
        self.inner
            .lock()
            .expect("memory s3 lock")
            .get(key)
            .cloned()
            .ok_or_else(|| S3Error::NotFound(key.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_s3_round_trips_objects() {
        let s3 = MemoryS3::new();
        s3.put("nginx/site.conf", b"server {}");
        assert_eq!(
            s3.get_object("nginx/site.conf").unwrap(),
            b"server {}".as_slice()
        );
        assert!(matches!(
            s3.get_object("missing"),
            Err(S3Error::NotFound(_))
        ));
    }
}
