//! **Hexagonal port** for loading catalog text and secret entries from a backend.
//! Production sync uses [`SsmSecretSource`] over [`SsmPort`](super::ssm::SsmPort);
//! [`LocalSecretSource`] reads `catalog.json` and per-profile env files for laptop dev.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::core::error::Error;
use crate::ports::ssm::{SsmError, SsmPort};
use crate::vault::host_store::read_profile_store;
use crate::vault::kek::AgeKek;

/// Snapshot file at the root of a local secrets directory.
pub const LOCAL_CATALOG_FILE: &str = "catalog.json";

/// Basename for profile env files: `{profile}.env`.
pub fn local_profile_env_basename(profile: &str) -> String {
    format!("{profile}.env")
}

/// Optional file payload for a catalog file entry: `{root}/files/{entry_name}`.
pub fn local_file_entry_path(root: &Path, entry_name: &str) -> PathBuf {
    root.join("files").join(entry_name)
}

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

/// Directory-backed secrets for local development (`catalog.json`, `{profile}.env`, optional `files/`).
pub struct LocalSecretSource {
    root: PathBuf,
}

impl LocalSecretSource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl SecretSource for LocalSecretSource {
    fn load_catalog(&self) -> Result<String, Error> {
        let path = self.root.join(LOCAL_CATALOG_FILE);
        std::fs::read_to_string(&path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                Error::SsmMissing(path.display().to_string())
            } else {
                Error::Io(err)
            }
        })
    }

    fn load_entry(&self, profile: &str, entry: &str) -> Result<String, Error> {
        load_local_entry(&self.root, profile, entry)
    }
}

/// Catalog from SSM or local `catalog.json`; secret **entries** from encrypted host store files.
pub struct HostStoreSecretSource<'a> {
    catalog: &'a dyn SecretSource,
    store_dir: PathBuf,
    kek: &'a AgeKek,
    cache: RefCell<HashMap<String, HashMap<String, String>>>,
}

impl<'a> HostStoreSecretSource<'a> {
    pub fn new(
        catalog: &'a dyn SecretSource,
        store_dir: impl Into<PathBuf>,
        kek: &'a AgeKek,
    ) -> Self {
        Self {
            catalog,
            store_dir: store_dir.into(),
            kek,
            cache: RefCell::new(HashMap::new()),
        }
    }

    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    fn load_profile_entries(&self, profile: &str) -> Result<HashMap<String, String>, Error> {
        let mut cache = self.cache.borrow_mut();
        if let Some(entries) = cache.get(profile) {
            return Ok(entries.clone());
        }
        let entries = read_profile_store(&self.store_dir, profile, self.kek)?;
        cache.insert(profile.to_owned(), entries.clone());
        Ok(entries)
    }
}

impl SecretSource for HostStoreSecretSource<'_> {
    fn load_catalog(&self) -> Result<String, Error> {
        self.catalog.load_catalog()
    }

    fn load_entry(&self, profile: &str, entry: &str) -> Result<String, Error> {
        let entries = self.load_profile_entries(profile)?;
        entries.get(entry).cloned().ok_or_else(|| {
            Error::SsmMissing(format!(
                "host-store:{profile}/{entry} (not in profile store file)"
            ))
        })
    }
}

fn load_local_entry(root: &Path, profile: &str, entry: &str) -> Result<String, Error> {
    let env_path = root.join(local_profile_env_basename(profile));
    let env_text = std::fs::read_to_string(&env_path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            Error::SsmMissing(env_path.display().to_string())
        } else {
            Error::Io(err)
        }
    })?;
    if let Some(value) = lookup_env_line(&env_text, entry)? {
        if let Some(relative) = value.strip_prefix('@') {
            let file_path = root.join(relative);
            return std::fs::read_to_string(&file_path).map_err(|err| {
                if err.kind() == std::io::ErrorKind::NotFound {
                    Error::SsmMissing(file_path.display().to_string())
                } else {
                    Error::Io(err)
                }
            });
        }
        return Ok(value);
    }
    let file_path = local_file_entry_path(root, entry);
    if file_path.is_file() {
        return std::fs::read_to_string(&file_path).map_err(Error::Io);
    }
    Err(Error::SsmMissing(format!(
        "local:{profile}/{entry} (not in {} or {})",
        env_path.display(),
        file_path.display()
    )))
}

fn lookup_env_line(text: &str, entry: &str) -> Result<Option<String>, Error> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::CatalogParse(format!(
                "local env line missing '=': {line}"
            )));
        };
        if key.trim() == entry {
            return Ok(Some(value.to_owned()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};
    use crate::ports::MemorySsm;
    use std::fs;

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

    fn temp_local_root(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "hev-local-src-{label}-{}-{id}",
            std::process::id()
        ))
    }

    #[test]
    fn local_secret_source_reads_catalog_and_env_entries() {
        let root = temp_local_root("env");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        const CATALOG: &str =
            r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#;
        fs::write(root.join(LOCAL_CATALOG_FILE), CATALOG).unwrap();
        fs::write(
            root.join("app-web.env"),
            "# comment\nDB_PASS=db-secret\n",
        )
        .unwrap();
        let source = LocalSecretSource::new(&root);
        assert_eq!(source.load_catalog().unwrap(), CATALOG);
        assert_eq!(
            source.load_entry("app-web", "DB_PASS").unwrap(),
            "db-secret"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_secret_source_reads_file_from_files_dir() {
        let root = temp_local_root("files-dir");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("files")).unwrap();
        fs::write(root.join(LOCAL_CATALOG_FILE), "{}").unwrap();
        fs::write(root.join("app-web.env"), "\n").unwrap();
        fs::write(root.join("files/client.key"), "client-bytes").unwrap();
        let source = LocalSecretSource::new(&root);
        assert_eq!(
            source.load_entry("app-web", "client.key").unwrap(),
            "client-bytes"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_secret_source_reads_file_via_at_path_in_env() {
        let root = temp_local_root("at-path");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("certs")).unwrap();
        fs::write(root.join(LOCAL_CATALOG_FILE), "{}").unwrap();
        fs::write(
            root.join("app-web.env"),
            "client.key=@certs/client.pem\n",
        )
        .unwrap();
        fs::write(root.join("certs/client.pem"), "pem-bytes").unwrap();
        let source = LocalSecretSource::new(&root);
        assert_eq!(
            source.load_entry("app-web", "client.key").unwrap(),
            "pem-bytes"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_secret_source_maps_missing_catalog() {
        let root = temp_local_root("no-catalog");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let source = LocalSecretSource::new(&root);
        assert!(matches!(
            source.load_catalog(),
            Err(Error::SsmMissing(path)) if path.contains(LOCAL_CATALOG_FILE)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_secret_source_maps_missing_profile_env() {
        let root = temp_local_root("no-env");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(LOCAL_CATALOG_FILE), "{}").unwrap();
        let source = LocalSecretSource::new(&root);
        assert!(matches!(
            source.load_entry("app-web", "DB_PASS"),
            Err(Error::SsmMissing(path)) if path.contains("app-web.env")
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_secret_source_maps_missing_at_path_target() {
        let root = temp_local_root("no-at");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(LOCAL_CATALOG_FILE), "{}").unwrap();
        fs::write(root.join("app-web.env"), "KEY=@missing.pem\n").unwrap();
        let source = LocalSecretSource::new(&root);
        assert!(matches!(
            source.load_entry("app-web", "KEY"),
            Err(Error::SsmMissing(path)) if path.contains("missing.pem")
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_secret_source_maps_missing_entry() {
        let root = temp_local_root("missing");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(LOCAL_CATALOG_FILE), "{}").unwrap();
        fs::write(root.join("app-web.env"), "DB_PASS=ok\n").unwrap();
        let source = LocalSecretSource::new(&root);
        assert!(matches!(
            source.load_entry("app-web", "MISSING"),
            Err(Error::SsmMissing(name)) if name.contains("MISSING")
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn host_store_secret_source_loads_catalog_and_store_entries() {
        use crate::vault::host_store::write_profile_store;
        use crate::vault::kek::AgeKek;
        use std::collections::HashMap;

        let catalog_root = temp_local_root("host-catalog");
        let store_root = temp_local_root("host-store");
        let _ = fs::remove_dir_all(&catalog_root);
        let _ = fs::remove_dir_all(&store_root);
        fs::create_dir_all(&catalog_root).unwrap();
        fs::create_dir_all(&store_root).unwrap();
        const CATALOG: &str =
            r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#;
        fs::write(catalog_root.join(LOCAL_CATALOG_FILE), CATALOG).unwrap();
        let kek = AgeKek::generate();
        let mut entries = HashMap::new();
        entries.insert("DB_PASS".into(), "from-store".into());
        write_profile_store(&store_root, "app-web", &entries, &kek).unwrap();
        let catalog = LocalSecretSource::new(&catalog_root);
        let source = HostStoreSecretSource::new(&catalog, &store_root, &kek);
        assert_eq!(source.load_catalog().unwrap(), CATALOG);
        assert_eq!(
            source.load_entry("app-web", "DB_PASS").unwrap(),
            "from-store"
        );
        let _ = fs::remove_dir_all(&catalog_root);
        let _ = fs::remove_dir_all(&store_root);
    }

    #[test]
    fn local_secret_source_rejects_malformed_env_line() {
        let root = temp_local_root("bad-line");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(LOCAL_CATALOG_FILE), "{}").unwrap();
        fs::write(root.join("app-web.env"), "NOT_A_LINE\n").unwrap();
        let source = LocalSecretSource::new(&root);
        assert!(matches!(
            source.load_entry("app-web", "NOT_A_LINE"),
            Err(Error::CatalogParse(_))
        ));
        let _ = fs::remove_dir_all(&root);
    }
}
