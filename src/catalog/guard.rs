//! Catalog allowlist checks used by sync/seal and serve.

use crate::catalog::parse::{Catalog, ProfileDefinition};
use crate::core::error::Error;
use crate::legacy::profile::{valid_env_value, valid_name, Kind};

/// One entry candidate for sealing into a local bundle.
pub struct SealEntry<'a> {
    pub name: String,
    pub kind: Kind,
    pub bytes: &'a [u8],
}

/// Refuse sealing when the profile or any entry is outside the catalog allowlist.
pub fn validate_seal_entries<'a>(
    catalog: &'a Catalog,
    profile_name: &str,
    entries: &[SealEntry<'_>],
) -> Result<&'a ProfileDefinition, Error> {
    let definition = catalog
        .profile(profile_name)
        .ok_or_else(|| Error::NotInCatalog(profile_name.to_owned()))?;
    if entries.is_empty() {
        return Err(Error::EmptyBundle);
    }
    for entry in entries {
        if !valid_name(&entry.name) {
            return Err(Error::InvalidName(entry.name.clone()));
        }
        if !definition.allows_seal(entry.kind, &entry.name) {
            tracing::info!(
                target: "host_env_vault::catalog",
                profile = profile_name,
                entry = %entry.name,
                kind = entry.kind.as_str(),
                "catalog refuse seal entry"
            );
            return Err(Error::EntryNotAllowed {
                name: entry.name.clone(),
                kind: entry.kind.as_str(),
                profile: profile_name.to_owned(),
            });
        }
        if entry.kind == Kind::Env && !valid_env_value(entry.bytes) {
            return Err(Error::InvalidEnvValue(entry.name.clone()));
        }
    }
    Ok(definition)
}

/// Refuse serving a runtime entry that is not on the profile's runtime list.
pub fn validate_serve_entry(
    catalog: &Catalog,
    profile_name: &str,
    kind: Kind,
    entry_name: &str,
) -> Result<(), Error> {
    let definition = catalog
        .profile(profile_name)
        .ok_or_else(|| Error::NotInCatalog(profile_name.to_owned()))?;
    if !definition.socket {
        tracing::info!(
            target: "host_env_vault::catalog",
            profile = profile_name,
            "catalog refuse serve on non-socket profile"
        );
        return Err(Error::EntryNotAllowed {
            name: entry_name.to_owned(),
            kind: kind.as_str(),
            profile: profile_name.to_owned(),
        });
    }
    if !definition.allows_serve(kind, entry_name) {
        tracing::info!(
            target: "host_env_vault::catalog",
            profile = profile_name,
            entry = entry_name,
            kind = kind.as_str(),
            "catalog refuse serve entry"
        );
        return Err(Error::EntryNotAllowed {
            name: entry_name.to_owned(),
            kind: kind.as_str(),
            profile: profile_name.to_owned(),
        });
    }
    Ok(())
}
