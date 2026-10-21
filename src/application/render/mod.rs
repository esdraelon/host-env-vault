//! **Render command** — unpack one profile from a local `.hev` through a slot,
//! write inject-listed secrets into an empty destination. No SSM at render time.

use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::application::manifest::{profile_is_stale, ENV_HOST_VAULT_STALE};
use crate::application::sync::{bundle_path, DEFAULT_STATE_DIR};
use crate::legacy::profile::Kind;
use crate::catalog::{load_catalog_snapshot, Catalog, ProfileDefinition};
use crate::core::error::Error;
use crate::core::slot::{SlotError, SlotTable};
use crate::legacy::render::{render, RenderMode};
use crate::vault::bundle::Entry;
use crate::vault::kek::AgeKek;
use crate::vault::local_bundle::open_profile_into_slot;

pub const RENDER_SLOT_INDEX: usize = 1;
const RENDER_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);

/// CLI paths for one render run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderOptions {
    pub identity_path: PathBuf,
    pub state_dir: PathBuf,
    pub dest: PathBuf,
    /// When set, overrides the catalog `gid` for file modes.
    pub gid_override: Option<u32>,
}

impl RenderOptions {
    pub fn new(
        identity_path: PathBuf,
        state_dir: PathBuf,
        dest: PathBuf,
        gid_override: Option<u32>,
    ) -> Self {
        Self {
            identity_path,
            state_dir,
            dest,
            gid_override,
        }
    }

    pub fn with_default_state_dir(
        identity_path: PathBuf,
        dest: PathBuf,
        gid_override: Option<u32>,
    ) -> Self {
        Self {
            identity_path,
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            dest,
            gid_override,
        }
    }
}

/// Load the local catalog snapshot and render one profile bundle.
pub fn render_from_vault(
    kek: &AgeKek,
    table: &mut SlotTable,
    profile_name: &str,
    options: &RenderOptions,
) -> Result<(), Error> {
    let catalog = load_catalog_snapshot(&options.state_dir)?;
    render_profile_with_catalog(kek, table, profile_name, &catalog, options)
}

/// Render using an already-parsed catalog (tests).
pub fn render_profile_with_catalog(
    kek: &AgeKek,
    table: &mut SlotTable,
    profile_name: &str,
    catalog: &Catalog,
    options: &RenderOptions,
) -> Result<(), Error> {
    let definition = catalog.profile(profile_name).ok_or_else(|| {
        tracing::info!(
            target: "host_env_vault::render_cmd",
            profile = profile_name,
            "render refuse profile not in catalog"
        );
        Error::NotInCatalog(profile_name.to_owned())
    })?;
    let bundle_bytes = std::fs::read(bundle_path(&options.state_dir, profile_name))?;
    let lease = table
        .acquire_sync(RENDER_SLOT_INDEX, RENDER_ACQUIRE_TIMEOUT)
        .map_err(map_slot_acquire)?;
    let render_result = (|| {
        let slot = table
            .slot_ref_mut(RENDER_SLOT_INDEX)
            .map_err(map_slot_acquire)?;
        let opened = open_profile_into_slot(catalog, &bundle_bytes, slot, lease, kek)?;
        if opened.profile != profile_name {
            return Err(Error::ProfileMismatch {
                found: opened.profile,
                expected: profile_name.to_owned(),
            });
        }
        let mut inject_entries = inject_only_entries(definition, &opened.entries);
        append_stale_inject_line(
            &mut inject_entries,
            profile_name,
            &options.state_dir,
        );
        let gid = options.gid_override.or(definition.gid);
        let mode = RenderMode::from_gid(gid);
        render(&options.dest, &inject_entries, mode)?;
        tracing::info!(
            target: "host_env_vault::render_cmd",
            profile = profile_name,
            dest = %options.dest.display(),
            inject_count = inject_entries.len(),
            "render wrote inject entries to destination"
        );
        Ok(())
    })();
    let _ = table.release(lease);
    render_result
}

fn append_stale_inject_line(
    inject: &mut Vec<Entry>,
    profile_name: &str,
    state_dir: &std::path::Path,
) {
    let stale = profile_is_stale(state_dir, profile_name);
    let value = if stale {
        Zeroizing::new(b"true".to_vec())
    } else {
        Zeroizing::new(b"false".to_vec())
    };
    inject.retain(|entry| entry.name != ENV_HOST_VAULT_STALE);
    inject.push(Entry {
        name: ENV_HOST_VAULT_STALE.to_owned(),
        kind: Kind::Env,
        bytes: value,
    });
    inject.sort_by(|a, b| a.name.cmp(&b.name));
}

fn inject_only_entries(definition: &ProfileDefinition, entries: &[Entry]) -> Vec<Entry> {
    let mut inject = Vec::new();
    let mut skipped_runtime = 0usize;
    for entry in entries {
        if definition.allows_inject(entry.kind, &entry.name) {
            inject.push(Entry {
                name: entry.name.clone(),
                kind: entry.kind,
                bytes: Zeroizing::new(entry.bytes.to_vec()),
            });
        } else if definition.allows_seal(entry.kind, &entry.name) {
            skipped_runtime += 1;
        }
    }
    if skipped_runtime > 0 {
        tracing::info!(
            target: "host_env_vault::render_cmd",
            profile = %definition.name,
            skipped_runtime,
            "render inject only skipping runtime entries"
        );
    }
    inject
}

fn map_slot_acquire(err: SlotError) -> Error {
    Error::CatalogParse(format!("render slot acquire: {err:?}"))
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod log_tests;

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::legacy::profile::Kind;

    #[test]
    fn render_slot_is_distinct_from_sync_slot() {
        assert_eq!(crate::application::sync::SYNC_SLOT_INDEX, 0);
        assert_eq!(RENDER_SLOT_INDEX, 1);
        assert!(RENDER_SLOT_INDEX < crate::core::slot::SLOT_COUNT);
    }

    #[test]
    fn inject_only_keeps_env_and_files_on_inject_lists() {
        use crate::catalog::parse_catalog_text;
        let catalog = parse_catalog_text(
            r#"{"profiles":[{"name":"p","inject":["A"],"runtime":["B"],"inject_files":["f.pem"],"runtime_files":["r.key"]}]}"#,
        )
        .unwrap();
        let def = catalog.profile("p").unwrap();
        let entries = vec![
            Entry {
                name: "A".into(),
                kind: Kind::Env,
                bytes: Zeroizing::new(b"1".to_vec()),
            },
            Entry {
                name: "B".into(),
                kind: Kind::Env,
                bytes: Zeroizing::new(b"2".to_vec()),
            },
            Entry {
                name: "f.pem".into(),
                kind: Kind::File,
                bytes: Zeroizing::new(b"pem".to_vec()),
            },
            Entry {
                name: "r.key".into(),
                kind: Kind::File,
                bytes: Zeroizing::new(b"key".to_vec()),
            },
        ];
        let inject = inject_only_entries(def, &entries);
        assert_eq!(inject.len(), 2);
        assert_eq!(inject[0].name, "A");
        assert_eq!(inject[1].name, "f.pem");
    }
}
