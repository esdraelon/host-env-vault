//! Flat encrypted JSON blob per profile (`{profile}.secrets.age`).

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::error::Error;
use crate::vault::kek::AgeKek;

use super::{set_mode, PROFILE_SECRETS_SUFFIX};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProfileStorePayload {
    entries: HashMap<String, String>,
}

/// Path to the flat encrypted store blob for one profile.
pub fn flat_store_path(store_dir: &Path, profile: &str) -> PathBuf {
    store_dir.join(format!("{profile}{PROFILE_SECRETS_SUFFIX}"))
}

/// Write entry map to a flat age-sealed file.
pub fn write_flat_profile_store(
    store_dir: &Path,
    profile: &str,
    entries: &HashMap<String, String>,
    kek: &AgeKek,
) -> Result<(), Error> {
    if !store_dir.as_os_str().is_empty() {
        fs::create_dir_all(store_dir)?;
    }
    let payload = ProfileStorePayload {
        entries: entries.clone(),
    };
    let json = serde_json::to_vec(&payload)
        .map_err(|err| Error::CatalogParse(format!("host store json encode: {err}")))?;
    let sealed = kek.seal_plaintext(&json)?;
    let path = flat_store_path(store_dir, profile);
    let tmp = store_dir.join(format!("{profile}{PROFILE_SECRETS_SUFFIX}.tmp"));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(&sealed)?;
    }
    set_mode(&tmp, 0o600)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Read and decrypt one flat profile store file.
pub fn read_flat_profile_store(
    store_dir: &Path,
    profile: &str,
    kek: &AgeKek,
) -> Result<HashMap<String, String>, Error> {
    let path = flat_store_path(store_dir, profile);
    let sealed = fs::read(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            Error::SsmMissing(path.display().to_string())
        } else {
            Error::Io(err)
        }
    })?;
    let plain = kek.open_sealed(&sealed)?;
    let payload: ProfileStorePayload = serde_json::from_slice(&plain).map_err(|err| {
        Error::CatalogParse(format!(
            "host store json decode {}: {err}",
            path.display()
        ))
    })?;
    Ok(payload.entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::kek::AgeKek;

    #[test]
    fn read_flat_maps_missing_file_to_ssm_missing() {
        let root = std::env::temp_dir().join(format!(
            "hev-flat-read-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let kek = AgeKek::generate();
        assert!(matches!(
            read_flat_profile_store(&root, "app-web", &kek),
            Err(Error::SsmMissing(path)) if path.contains("app-web.secrets.age")
        ));
        let _ = std::fs::remove_dir_all(&root);
    }
}
