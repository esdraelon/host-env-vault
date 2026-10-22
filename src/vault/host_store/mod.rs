//! Per-profile encrypted host store files (`{profile}.secrets.age`).

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::error::Error;
use crate::vault::kek::AgeKek;

/// Encrypted store filename suffix for one catalog profile.
pub const PROFILE_SECRETS_SUFFIX: &str = ".secrets.age";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProfileStorePayload {
    entries: HashMap<String, String>,
}

/// Path to the encrypted store blob for one profile.
pub fn profile_store_path(store_dir: &Path, profile: &str) -> PathBuf {
    store_dir.join(format!("{profile}{PROFILE_SECRETS_SUFFIX}"))
}

/// Write entry map to disk sealed with the host KEK.
pub fn write_profile_store(
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
    let path = profile_store_path(store_dir, profile);
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

/// Read and decrypt one profile store file.
pub fn read_profile_store(
    store_dir: &Path,
    profile: &str,
    kek: &AgeKek,
) -> Result<HashMap<String, String>, Error> {
    let path = profile_store_path(store_dir, profile);
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

fn set_mode(path: &Path, mode: u32) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Profile names that have a `{profile}.secrets.age` file in `store_dir`.
pub fn list_stored_profiles(store_dir: &Path) -> Result<Vec<String>, Error> {
    let mut names = Vec::new();
    if !store_dir.is_dir() {
        return Ok(names);
    }
    for entry in fs::read_dir(store_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if let Some(profile) = file_name.strip_suffix(PROFILE_SECRETS_SUFFIX) {
            if !profile.is_empty() {
                names.push(profile.to_owned());
            }
        }
    }
    names.sort_unstable();
    Ok(names)
}

/// Create the store root with restrictive permissions.
pub fn ensure_store_dir(store_dir: &Path) -> Result<(), Error> {
    if store_dir.as_os_str().is_empty() {
        return Err(Error::CatalogParse("store_dir path is empty".into()));
    }
    fs::create_dir_all(store_dir)?;
    set_mode(store_dir, 0o700)?;
    Ok(())
}

#[cfg(test)]
mod behavior_tests;
