//! **Local bundle command** — seal and open one catalog profile through a slot.
//! Sync will call this path; only one profile occupies a slot at a time.

use zeroize::Zeroizing;

use crate::bundle::{self, Entry, Opened};
use crate::catalog::{validate_seal_entries, Catalog, SealEntry};
use crate::error::Error;
use crate::kek::AgeKek;
use crate::profile::Kind;
use crate::slot::{Slot, SlotError, SlotLease};

/// Load allowlisted entries into a slot, then seal an `HEV1` bundle from that slot.
pub fn seal_profile_in_slot(
    catalog: &Catalog,
    slot: &mut Slot,
    lease: SlotLease,
    profile_name: &str,
    entries: &[SealEntry<'_>],
    kek: &AgeKek,
) -> Result<Vec<u8>, Error> {
    validate_seal_entries(catalog, profile_name, entries)?;
    reject_duplicate_seal_names(entries)?;
    load_seal_entries_into_slot(slot, lease, profile_name, entries)?;
    seal_slot_contents(slot, kek)
}

/// Decrypt a bundle and unpack it into the slot after catalog checks.
pub fn open_profile_into_slot(
    catalog: &Catalog,
    bundle: &[u8],
    slot: &mut Slot,
    lease: SlotLease,
    kek: &AgeKek,
) -> Result<Opened, Error> {
    let opened = bundle::open_bytes(bundle, kek)?;
    validate_opened_against_catalog(catalog, &opened)?;
    unpack_opened_into_slot(slot, lease, &opened)?;
    tracing::info!(
        target: "host_env_vault::local_bundle",
        profile = %opened.profile,
        entry_count = opened.entries.len(),
        "local bundle open into slot"
    );
    Ok(opened)
}

fn reject_duplicate_seal_names(entries: &[SealEntry<'_>]) -> Result<(), Error> {
    let mut seen = Vec::with_capacity(entries.len());
    for entry in entries {
        if seen.contains(&entry.name.as_str()) {
            return Err(Error::DuplicateEntry(entry.name.clone()));
        }
        seen.push(entry.name.as_str());
    }
    Ok(())
}

fn load_seal_entries_into_slot(
    slot: &mut Slot,
    lease: SlotLease,
    profile_name: &str,
    entries: &[SealEntry<'_>],
) -> Result<(), Error> {
    slot.set_profile_name(lease, profile_name.as_bytes())
        .map_err(map_slot)?;
    for entry in entries {
        match entry.kind {
            Kind::Env => slot
                .put_secret(lease, entry.name.as_bytes(), entry.bytes)
                .map_err(map_slot)?,
            Kind::File => slot
                .put_document(lease, entry.name.as_bytes(), entry.bytes)
                .map_err(map_slot)?,
        }
    }
    Ok(())
}

fn seal_slot_contents(slot: &Slot, kek: &AgeKek) -> Result<Vec<u8>, Error> {
    let profile = std::str::from_utf8(slot.profile_name_bytes())
        .map_err(|_| Error::RuntimeBody)?;
    let entries = entries_from_slot(slot)?;
    tracing::info!(
        target: "host_env_vault::local_bundle",
        profile,
        entry_count = entries.len(),
        "local bundle seal from slot"
    );
    bundle::seal_bytes(profile, entries, kek)
}

fn entries_from_slot(slot: &Slot) -> Result<Vec<Entry>, Error> {
    if slot.profile_name_bytes().is_empty() {
        return Err(Error::EmptyBundle);
    }
    let mut entries = Vec::new();
    for index in 0..slot.secret_count() as usize {
        let name = slot
            .secret_name_bytes(index)
            .ok_or(Error::RuntimeBody)?;
        let value = slot.secret_bytes(index).ok_or(Error::RuntimeBody)?;
        entries.push(Entry {
            name: std::str::from_utf8(name)
                .map_err(|_| Error::RuntimeBody)?
                .to_owned(),
            kind: Kind::Env,
            bytes: Zeroizing::new(value.to_vec()),
        });
    }
    for index in 0..slot.document_count() as usize {
        let name = slot
            .document_name_bytes(index)
            .ok_or(Error::RuntimeBody)?;
        let value = slot.document_bytes(index).ok_or(Error::RuntimeBody)?;
        entries.push(Entry {
            name: std::str::from_utf8(name)
                .map_err(|_| Error::RuntimeBody)?
                .to_owned(),
            kind: Kind::File,
            bytes: Zeroizing::new(value.to_vec()),
        });
    }
    if entries.is_empty() {
        return Err(Error::EmptyBundle);
    }
    Ok(entries)
}

fn validate_opened_against_catalog(catalog: &Catalog, opened: &Opened) -> Result<(), Error> {
    let definition = catalog.profile(&opened.profile).ok_or_else(|| {
        tracing::info!(
            target: "host_env_vault::local_bundle",
            profile = %opened.profile,
            "local bundle refuse open not in catalog"
        );
        Error::NotInCatalog(opened.profile.clone())
    })?;
    for entry in &opened.entries {
        if !definition.allows_seal(entry.kind, &entry.name) {
            tracing::info!(
                target: "host_env_vault::local_bundle",
                profile = %opened.profile,
                entry = %entry.name,
                kind = entry.kind.as_str(),
                "local bundle refuse open entry"
            );
            return Err(Error::EntryNotAllowed {
                name: entry.name.clone(),
                kind: entry.kind.as_str(),
                profile: opened.profile.clone(),
            });
        }
    }
    Ok(())
}

fn unpack_opened_into_slot(
    slot: &mut Slot,
    lease: SlotLease,
    opened: &Opened,
) -> Result<(), Error> {
    slot.set_profile_name(lease, opened.profile.as_bytes())
        .map_err(map_slot)?;
    for entry in &opened.entries {
        match entry.kind {
            Kind::Env => slot
                .put_secret(lease, entry.name.as_bytes(), &entry.bytes)
                .map_err(map_slot)?,
            Kind::File => slot
                .put_document(lease, entry.name.as_bytes(), &entry.bytes)
                .map_err(map_slot)?,
        }
    }
    Ok(())
}

fn map_slot(err: SlotError) -> Error {
    match err {
        SlotError::OversizeName => Error::InvalidName("entry or profile name oversize".into()),
        SlotError::OversizeSecret | SlotError::OversizeDocument => Error::RuntimeBody,
        SlotError::StaleGeneration => Error::RuntimeBody,
        SlotError::TooManySecrets | SlotError::TooManyDocuments => Error::RuntimeBody,
        other => Error::CatalogParse(format!("slot error: {other:?}")),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::profile::Kind;

    #[test]
    fn reject_duplicate_seal_entry_names() {
        let entries = vec![
            SealEntry {
                name: "DB_PASS".into(),
                kind: Kind::Env,
                bytes: b"1",
            },
            SealEntry {
                name: "DB_PASS".into(),
                kind: Kind::Env,
                bytes: b"2",
            },
        ];
        assert!(matches!(
            reject_duplicate_seal_names(&entries),
            Err(Error::DuplicateEntry(_))
        ));
    }
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod log_tests;
