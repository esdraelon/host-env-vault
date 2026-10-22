//! **Store command** — CRUD for encrypted per-profile host store files (transition mode).

use std::io;
use std::path::{Path, PathBuf};

use tracing::info;

use crate::application::sync::load_or_create_identity;
use crate::catalog::{parse_catalog_text, ProfileDefinition};
use crate::core::error::Error;
use crate::ports::{LocalSecretSource, SecretSource};
use crate::vault::host_store::{
    ensure_store_dir, list_stored_profiles, profile_path_for_backend, read_profile_store,
    resolve_store_backend, write_profile_store_with_backend, StoreBackend,
};
use crate::vault::kek::AgeKek;

pub mod export;
pub mod interactive;

pub use export::{
    store_export_ssm, StoreExportFormat, StoreExportOutput, StoreExportParameter,
    StoreExportSsmOptions,
};
pub use interactive::{resolve_field, resolve_secret_value};

/// Resolved paths for a store subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOptions {
    pub identity_path: PathBuf,
    pub store_dir: PathBuf,
}

/// One profile row for `store list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreProfileListing {
    pub profile: String,
    pub entries: Vec<String>,
}

/// Initialize store directory and ensure host age identity exists.
pub fn store_init(options: &StoreOptions) -> Result<(), Error> {
    ensure_store_dir(&options.store_dir)?;
    let _ = load_or_create_identity(&options.identity_path)?;
    info!(
        target: "host_env_vault::store",
        store_dir = %options.store_dir.display(),
        "store init: layout ready"
    );
    Ok(())
}

/// Upsert one entry in the profile store file.
pub fn store_put(
    options: &StoreOptions,
    profile: &str,
    entry: &str,
    value: &str,
    kek: &AgeKek,
    create_backend: StoreBackend,
) -> Result<(), Error> {
    validate_entry_names(profile, entry)?;
    let mut entries = read_profile_store(&options.store_dir, profile, kek).unwrap_or_default();
    entries.insert(entry.to_owned(), value.to_owned());
    write_profile_store_with_backend(
        &options.store_dir,
        profile,
        &entries,
        kek,
        create_backend,
    )?;
    info!(
        target: "host_env_vault::store",
        profile = %profile,
        entry = %entry,
        "store put: entry upserted"
    );
    Ok(())
}

/// Read one entry; when `show_plaintext` is false, return a masked string.
pub fn store_get(
    options: &StoreOptions,
    profile: &str,
    entry: &str,
    kek: &AgeKek,
    show_plaintext: bool,
) -> Result<String, Error> {
    let entries = read_profile_store(&options.store_dir, profile, kek)?;
    let value = entries.get(entry).cloned().ok_or_else(|| {
        Error::SsmMissing(format!("host-store:{profile}/{entry} (not in profile store file)"))
    })?;
    Ok(if show_plaintext {
        value
    } else {
        mask_secret(&value)
    })
}

/// List profiles on disk and their entry names (decrypts each profile file).
pub fn store_list(options: &StoreOptions, kek: &AgeKek) -> Result<Vec<StoreProfileListing>, Error> {
    let profiles = list_stored_profiles(&options.store_dir)?;
    let mut out = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let entries_map = read_profile_store(&options.store_dir, &profile, kek)?;
        let mut entries: Vec<_> = entries_map.keys().cloned().collect();
        entries.sort_unstable();
        out.push(StoreProfileListing { profile, entries });
    }
    Ok(out)
}

/// Remove one entry; deletes the profile file when the last entry is removed.
pub fn store_remove(
    options: &StoreOptions,
    profile: &str,
    entry: &str,
    kek: &AgeKek,
) -> Result<(), Error> {
    let backend = resolve_store_backend(&options.store_dir, profile)?;
    let mut entries = read_profile_store(&options.store_dir, profile, kek)?;
    if entries.remove(entry).is_none() {
        return Err(Error::SsmMissing(format!(
            "host-store:{profile}/{entry} (not in profile store file)"
        )));
    }
    if entries.is_empty() {
        let path = profile_path_for_backend(&options.store_dir, profile, backend);
        std::fs::remove_file(&path)?;
        info!(
            target: "host_env_vault::store",
            profile = %profile,
            "store remove: profile file deleted"
        );
    } else {
        write_profile_store_with_backend(
            &options.store_dir,
            profile,
            &entries,
            kek,
            backend,
        )?;
        info!(
            target: "host_env_vault::store",
            profile = %profile,
            entry = %entry,
            "store remove: entry deleted"
        );
    }
    Ok(())
}

/// Import secrets from a local dev directory (`catalog.json`, `{profile}.env`, `files/`).
pub fn store_import_from_dev_dir(
    options: &StoreOptions,
    dev_dir: &Path,
    profile_filter: Option<&str>,
    kek: &AgeKek,
    create_backend: StoreBackend,
) -> Result<usize, Error> {
    let source = LocalSecretSource::new(dev_dir);
    let catalog_text = source.load_catalog()?;
    let catalog = parse_catalog_text(&catalog_text)?;
    let mut imported = 0usize;
    let mut names: Vec<_> = catalog.profile_names().collect();
    names.sort_unstable();
    for name in names {
        if let Some(filter) = profile_filter {
            if name != filter {
                continue;
            }
        }
        let Some(definition) = catalog.profile(name) else {
            continue;
        };
        imported += import_profile_from_local_source(
            options,
            &source,
            definition,
            kek,
            create_backend,
        )?;
    }
    info!(
        target: "host_env_vault::store",
        from = %dev_dir.display(),
        count = imported,
        "store import: dev layout complete"
    );
    Ok(imported)
}

/// Import all `KEY=value` lines from one env file into a profile store.
pub fn store_import_from_env_file(
    options: &StoreOptions,
    profile: &str,
    env_path: &Path,
    kek: &AgeKek,
    create_backend: StoreBackend,
) -> Result<usize, Error> {
    validate_profile_name(profile)?;
    let root = env_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let source = LocalSecretSource::new(root);
    let text = std::fs::read_to_string(env_path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            Error::SsmMissing(env_path.display().to_string())
        } else {
            Error::Io(err)
        }
    })?;
    let mut imported = 0usize;
    let mut entries = read_profile_store(&options.store_dir, profile, kek).unwrap_or_default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, _value_part)) = line.split_once('=') else {
            return Err(Error::CatalogParse(format!(
                "env import line missing '=': {line}"
            )));
        };
        let key = key.trim();
        validate_entry_names(profile, key)?;
        let value = source.load_entry(profile, key)?;
        entries.insert(key.to_owned(), value);
        imported += 1;
    }
    if imported > 0 {
        write_profile_store_with_backend(
            &options.store_dir,
            profile,
            &entries,
            kek,
            create_backend,
        )?;
    }
    info!(
        target: "host_env_vault::store",
        profile = %profile,
        from = %env_path.display(),
        count = imported,
        "store import: env file complete"
    );
    Ok(imported)
}

/// Re-encrypt every profile store file with a new host KEK.
pub fn store_rekey(
    options: &StoreOptions,
    old_kek: &AgeKek,
    new_kek: &AgeKek,
) -> Result<usize, Error> {
    let profiles = list_stored_profiles(&options.store_dir)?;
    let mut count = 0usize;
    for profile in profiles {
        let backend = resolve_store_backend(&options.store_dir, &profile)?;
        let entries = read_profile_store(&options.store_dir, &profile, old_kek)?;
        write_profile_store_with_backend(
            &options.store_dir,
            &profile,
            &entries,
            new_kek,
            backend,
        )?;
        count += 1;
    }
    info!(
        target: "host_env_vault::store",
        profiles = count,
        "store rekey: profiles rotated"
    );
    Ok(count)
}

fn import_profile_from_local_source(
    options: &StoreOptions,
    source: &LocalSecretSource,
    definition: &ProfileDefinition,
    kek: &AgeKek,
    create_backend: StoreBackend,
) -> Result<usize, Error> {
    let profile = definition.name.as_str();
    let mut entry_names = Vec::new();
    entry_names.extend(definition.inject_env().iter().cloned());
    entry_names.extend(definition.runtime_env().iter().cloned());
    entry_names.extend(definition.inject_files().iter().cloned());
    entry_names.extend(definition.runtime_files().iter().cloned());
    entry_names.sort_unstable();
    entry_names.dedup();
    let mut imported = 0usize;
    let mut entries = read_profile_store(&options.store_dir, profile, kek).unwrap_or_default();
    for entry in entry_names {
        let value = source.load_entry(profile, &entry)?;
        entries.insert(entry, value);
        imported += 1;
    }
    if imported > 0 {
        write_profile_store_with_backend(
            &options.store_dir,
            profile,
            &entries,
            kek,
            create_backend,
        )?;
    }
    Ok(imported)
}

fn validate_profile_name(profile: &str) -> Result<(), Error> {
    if profile.is_empty() {
        return Err(Error::CatalogParse("profile name is empty".into()));
    }
    if !crate::legacy::profile::valid_name(profile) {
        return Err(Error::CatalogParse(format!("invalid profile name `{profile}`")));
    }
    Ok(())
}

fn validate_entry_names(profile: &str, entry: &str) -> Result<(), Error> {
    validate_profile_name(profile)?;
    if entry.is_empty() {
        return Err(Error::CatalogParse("entry name is empty".into()));
    }
    if !crate::legacy::profile::valid_name(entry) {
        return Err(Error::CatalogParse(format!("invalid entry name `{entry}`")));
    }
    Ok(())
}

/// Mask a secret for safe `store get` output.
pub fn mask_secret(value: &str) -> String {
    if value.is_empty() {
        return "(empty)".into();
    }
    format!("*** ({} bytes)", value.len())
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod export_tests;

#[cfg(test)]
mod log_tests;
