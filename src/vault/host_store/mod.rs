//! Per-profile encrypted host store files (`{profile}.secrets.age` or `{profile}.secrets.db`).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::error::Error;
use crate::vault::kek::AgeKek;

mod flat;
mod sqlite;

pub use flat::flat_store_path;
pub use sqlite::sqlite_store_path;

/// Flat encrypted JSON blob suffix (M19 engine).
pub const PROFILE_SECRETS_SUFFIX: &str = ".secrets.age";

/// Age-encrypted SQLite file suffix (M22 engine).
pub const PROFILE_SQLITE_SUFFIX: &str = ".secrets.db";

/// Host store backend selected from the profile file extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreBackend {
    Flat,
    Sqlite,
}

impl StoreBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flat => "flat",
            Self::Sqlite => "sqlite",
        }
    }

    pub fn parse_cli(value: &str) -> Result<Self, Error> {
        match value {
            "flat" | "age" => Ok(Self::Flat),
            "sqlite" | "db" => Ok(Self::Sqlite),
            other => Err(Error::CatalogParse(format!(
                "unknown store backend `{other}` (expected flat or sqlite)"
            ))),
        }
    }
}

/// Path to the encrypted store blob for one profile (flat engine; backward compatible).
pub fn profile_store_path(store_dir: &Path, profile: &str) -> PathBuf {
    flat_store_path(store_dir, profile)
}

/// Resolve backend from on-disk profile store files.
pub fn resolve_store_backend(store_dir: &Path, profile: &str) -> Result<StoreBackend, Error> {
    let flat = flat_store_path(store_dir, profile);
    let sqlite = sqlite_store_path(store_dir, profile);
    let flat_exists = flat.is_file();
    let sqlite_exists = sqlite.is_file();
    match (flat_exists, sqlite_exists) {
        (true, true) => Err(Error::CatalogParse(format!(
            "ambiguous host store for profile `{profile}`: both {} and {} exist",
            flat.display(),
            sqlite.display()
        ))),
        (true, false) => Ok(StoreBackend::Flat),
        (false, true) => Ok(StoreBackend::Sqlite),
        (false, false) => Err(Error::SsmMissing(format!(
            "host store missing for profile `{profile}` (expected {} or {})",
            flat.display(),
            sqlite.display()
        ))),
    }
}

/// Path for a profile store file for the given backend.
pub fn profile_path_for_backend(
    store_dir: &Path,
    profile: &str,
    backend: StoreBackend,
) -> PathBuf {
    match backend {
        StoreBackend::Flat => flat_store_path(store_dir, profile),
        StoreBackend::Sqlite => sqlite_store_path(store_dir, profile),
    }
}

/// Write entry map using an existing backend or `create_backend` when the profile file is new.
pub fn write_profile_store(
    store_dir: &Path,
    profile: &str,
    entries: &HashMap<String, String>,
    kek: &AgeKek,
) -> Result<(), Error> {
    write_profile_store_with_backend(store_dir, profile, entries, kek, StoreBackend::Flat)
}

/// Write entry map, creating a new profile file with `create_backend` when none exists yet.
pub fn write_profile_store_with_backend(
    store_dir: &Path,
    profile: &str,
    entries: &HashMap<String, String>,
    kek: &AgeKek,
    create_backend: StoreBackend,
) -> Result<(), Error> {
    let backend = match resolve_store_backend(store_dir, profile) {
        Ok(existing) => existing,
        Err(Error::SsmMissing(_)) => create_backend,
        Err(err) => return Err(err),
    };
    match backend {
        StoreBackend::Flat => flat::write_flat_profile_store(store_dir, profile, entries, kek),
        StoreBackend::Sqlite => sqlite::write_sqlite_profile_store(store_dir, profile, entries, kek),
    }
}

/// Read and decrypt one profile store file (engine from extension).
pub fn read_profile_store(
    store_dir: &Path,
    profile: &str,
    kek: &AgeKek,
) -> Result<HashMap<String, String>, Error> {
    match resolve_store_backend(store_dir, profile)? {
        StoreBackend::Flat => flat::read_flat_profile_store(store_dir, profile, kek),
        StoreBackend::Sqlite => sqlite::read_sqlite_profile_store(store_dir, profile, kek),
    }
}

/// Profile names that have a host store file in `store_dir` (either backend).
pub fn list_stored_profiles(store_dir: &Path) -> Result<Vec<String>, Error> {
    let mut names = Vec::new();
    if !store_dir.is_dir() {
        return Ok(names);
    }
    let mut seen = HashMap::<String, StoreBackend>::new();
    for entry in fs::read_dir(store_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if let Some(profile) = file_name.strip_suffix(PROFILE_SECRETS_SUFFIX) {
            if profile.is_empty() {
                continue;
            }
            record_profile(&mut seen, profile, StoreBackend::Flat)?;
            continue;
        }
        if let Some(profile) = file_name.strip_suffix(PROFILE_SQLITE_SUFFIX) {
            if profile.is_empty() {
                continue;
            }
            record_profile(&mut seen, profile, StoreBackend::Sqlite)?;
        }
    }
    names.extend(seen.keys().cloned());
    names.sort_unstable();
    Ok(names)
}

fn record_profile(
    seen: &mut HashMap<String, StoreBackend>,
    profile: &str,
    backend: StoreBackend,
) -> Result<(), Error> {
    if let Some(existing) = seen.get(profile) {
        if *existing != backend {
            return Err(Error::CatalogParse(format!(
                "ambiguous host store for profile `{profile}`: both flat and sqlite files exist"
            )));
        }
        return Ok(());
    }
    seen.insert(profile.to_owned(), backend);
    Ok(())
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

pub(super) fn set_mode(path: &Path, mode: u32) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(test)]
mod behavior_tests;
