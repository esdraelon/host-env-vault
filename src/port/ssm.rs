//! **Hexagonal port** for AWS SSM Parameter Store. Production uses the SDK;
//! tests inject [`MemorySsm`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Failures fetching a parameter. Messages never include secret bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SsmError {
    #[error("parameter `{0}` not found")]
    NotFound(String),
    #[error("parameter store unavailable")]
    Unavailable,
}

/// Read-only SSM access for catalog and secret parameters.
pub trait SsmPort {
    fn get_parameter(&self, name: &str) -> Result<String, SsmError>;
}

/// In-memory parameter map for unit tests and integration stubs.
#[derive(Debug, Default, Clone)]
pub struct MemorySsm {
    inner: Arc<Mutex<HashMap<String, String>>>,
}

impl MemorySsm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&self, name: impl Into<String>, value: impl Into<String>) {
        self.inner
            .lock()
            .expect("memory ssm lock")
            .insert(name.into(), value.into());
    }
}

impl SsmPort for MemorySsm {
    fn get_parameter(&self, name: &str) -> Result<String, SsmError> {
        self.inner
            .lock()
            .expect("memory ssm lock")
            .get(name)
            .cloned()
            .ok_or_else(|| SsmError::NotFound(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_ssm_round_trips_parameters() {
        let ssm = MemorySsm::new();
        ssm.put("/amtgard/vault/profiles", "{}");
        assert_eq!(
            ssm.get_parameter("/amtgard/vault/profiles").unwrap(),
            "{}"
        );
        assert!(matches!(
            ssm.get_parameter("/missing"),
            Err(SsmError::NotFound(_))
        ));
    }
}
