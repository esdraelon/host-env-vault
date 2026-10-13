//! **Hexagonal port** for loading catalog text and secret entries from a backend.
//! Production sync uses [`SsmSecretSource`] over [`SsmPort`](super::ssm::SsmPort); M11 adds local files.

use crate::core::error::Error;
use crate::ports::ssm::{SsmError, SsmPort};

/// SSM parameter path for one secret entry under a profile.
pub fn ssm_entry_parameter(
    secrets_prefix: &str,
    profile_name: &str,
    entry_name: &str,
) -> String {
    let prefix = secrets_prefix.trim_end_matches('/');
    format!("{prefix}/{profile_name}/{entry_name}")
}

/// Read-only access to the profile catalog and per-profile secret values.
pub trait SecretSource {
    fn load_catalog(&self) -> Result<String, Error>;
    fn load_entry(&self, profile: &str, entry: &str) -> Result<String, Error>;
}

/// SSM Parameter Store as the secret backend (catalog + `{prefix}/{profile}/{entry}`).
pub struct SsmSecretSource<'a> {
    catalog_param: String,
    secrets_prefix: String,
    ssm: &'a dyn SsmPort,
}

impl<'a> SsmSecretSource<'a> {
    pub fn new(
        catalog_param: impl Into<String>,
        secrets_prefix: impl Into<String>,
        ssm: &'a dyn SsmPort,
    ) -> Self {
        Self {
            catalog_param: catalog_param.into(),
            secrets_prefix: secrets_prefix.into(),
            ssm,
        }
    }
}

impl SecretSource for SsmSecretSource<'_> {
    fn load_catalog(&self) -> Result<String, Error> {
        self.ssm
            .get_parameter(&self.catalog_param)
            .map_err(map_ssm)
    }

    fn load_entry(&self, profile: &str, entry: &str) -> Result<String, Error> {
        let param = ssm_entry_parameter(&self.secrets_prefix, profile, entry);
        self.ssm.get_parameter(&param).map_err(map_ssm)
    }
}

fn map_ssm(err: SsmError) -> Error {
    match err {
        SsmError::NotFound(name) => Error::SsmMissing(name),
        SsmError::Unavailable => Error::CatalogParse("ssm unavailable".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};
    use crate::ports::MemorySsm;

    const CATALOG: &str = r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#;

    #[test]
    fn ssm_secret_source_loads_catalog_and_entry() {
        let ssm = MemorySsm::new();
        ssm.put(DEFAULT_CATALOG_PARAMETER, CATALOG);
        ssm.put("/host-env-vault/app-web/DB_PASS", "db-secret");
        let source = SsmSecretSource::new(
            DEFAULT_CATALOG_PARAMETER,
            DEFAULT_SECRETS_PREFIX,
            &ssm,
        );
        assert_eq!(source.load_catalog().unwrap(), CATALOG);
        assert_eq!(
            source.load_entry("app-web", "DB_PASS").unwrap(),
            "db-secret"
        );
    }

    #[test]
    fn ssm_secret_source_maps_missing_parameter() {
        let ssm = MemorySsm::new();
        let source = SsmSecretSource::new(
            DEFAULT_CATALOG_PARAMETER,
            DEFAULT_SECRETS_PREFIX,
            &ssm,
        );
        assert!(matches!(
            source.load_catalog(),
            Err(Error::SsmMissing(_))
        ));
        ssm.put(DEFAULT_CATALOG_PARAMETER, CATALOG);
        assert!(matches!(
            source.load_entry("app-web", "MISSING"),
            Err(Error::SsmMissing(name)) if name.contains("MISSING")
        ));
    }
}
