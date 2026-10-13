//! **Fetch-documents command** — load catalog S3 keys into the sync slot without SSM.

use std::path::PathBuf;
use std::time::Duration;

use crate::application::documents::load_documents_into_slot;
use crate::application::sync::{DEFAULT_STATE_DIR, SYNC_SLOT_INDEX};
use crate::catalog::load_catalog_snapshot;
use crate::core::error::Error;
use crate::core::slot::{SlotError, SlotTable};
use crate::ports::S3Port;

const FETCH_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchDocumentsOptions {
    pub state_dir: PathBuf,
    pub s3_prefix: String,
    pub profile: String,
}

impl FetchDocumentsOptions {
    pub fn new(
        state_dir: PathBuf,
        s3_prefix: impl Into<String>,
        profile: impl Into<String>,
    ) -> Self {
        Self {
            state_dir,
            s3_prefix: s3_prefix.into(),
            profile: profile.into(),
        }
    }

    pub fn with_default_state_dir(
        s3_prefix: impl Into<String>,
        profile: impl Into<String>,
    ) -> Self {
        Self {
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            s3_prefix: s3_prefix.into(),
            profile: profile.into(),
        }
    }
}

/// Pull document keys for one profile from S3 into the sync slot (test and install hook).
pub fn fetch_profile_documents(
    s3: &dyn S3Port,
    table: &mut SlotTable,
    options: &FetchDocumentsOptions,
) -> Result<(), Error> {
    let catalog = load_catalog_snapshot(&options.state_dir)?;
    let definition = catalog.profile(&options.profile).ok_or_else(|| {
        tracing::info!(
            target: "host_env_vault::fetch_documents",
            profile = %options.profile,
            "fetch documents refuse profile not in catalog"
        );
        Error::NotInCatalog(options.profile.clone())
    })?;
    if definition.document_keys().is_empty() {
        return Err(Error::EmptyBundle);
    }
    let lease = table
        .acquire_sync(SYNC_SLOT_INDEX, FETCH_ACQUIRE_TIMEOUT)
        .map_err(map_slot_acquire)?;
    let result = (|| {
        let slot = table
            .slot_ref_mut(SYNC_SLOT_INDEX)
            .map_err(map_slot_acquire)?;
        slot.set_profile_name(lease, options.profile.as_bytes())
            .map_err(map_slot)?;
        load_documents_into_slot(s3, &options.s3_prefix, definition, slot, lease)
    })();
    let _ = table.release(lease);
    result
}

fn map_slot_acquire(err: SlotError) -> Error {
    Error::CatalogParse(format!("fetch documents slot acquire: {err:?}"))
}

fn map_slot(err: SlotError) -> Error {
    match err {
        SlotError::OversizeName => Error::InvalidName("profile name oversize".into()),
        SlotError::StaleGeneration => Error::RuntimeBody,
        other => Error::CatalogParse(format!("slot error: {other:?}")),
    }
}

#[cfg(test)]
mod log_tests;

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use crate::catalog::write_catalog_snapshot;
    use crate::ports::MemoryS3;
    use std::path::PathBuf;

    fn temp_state_dir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "hev-fetch-docs-{label}-{}-{id}",
            std::process::id()
        ))
    }

    #[test]
    fn fetch_documents_refuses_unknown_profile() {
        let state_dir = temp_state_dir("unknown");
        let _ = std::fs::remove_dir_all(&state_dir);
        std::fs::create_dir_all(&state_dir).unwrap();
        write_catalog_snapshot(
            &state_dir,
            r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["site.conf"]}]}"#,
        )
        .unwrap();
        let s3 = MemoryS3::new();
        let mut table = SlotTable::new();
        let options = FetchDocumentsOptions::new(state_dir.clone(), "prefix", "missing");
        assert!(matches!(
            fetch_profile_documents(&s3, &mut table, &options),
            Err(crate::core::error::Error::NotInCatalog(_))
        ));
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[test]
    fn fetch_documents_refuses_profile_without_document_keys() {
        let state_dir = temp_state_dir("empty-docs");
        let _ = std::fs::remove_dir_all(&state_dir);
        std::fs::create_dir_all(&state_dir).unwrap();
        write_catalog_snapshot(
            &state_dir,
            r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":[]}]}"#,
        )
        .unwrap();
        let s3 = MemoryS3::new();
        let mut table = SlotTable::new();
        let options = FetchDocumentsOptions::new(state_dir.clone(), "prefix", "nginx");
        assert!(matches!(
            fetch_profile_documents(&s3, &mut table, &options),
            Err(crate::core::error::Error::EmptyBundle)
        ));
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[test]
    fn fetch_documents_loads_nginx_paths_from_fake_s3() {
        let state_dir = temp_state_dir("nginx");
        let _ = std::fs::remove_dir_all(&state_dir);
        std::fs::create_dir_all(&state_dir).unwrap();
        let catalog = r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["nginx/site.conf"]}]}"#;
        write_catalog_snapshot(&state_dir, catalog).unwrap();
        let s3 = MemoryS3::new();
        s3.put("prefix/nginx/site.conf", b"server {}");
        let mut table = SlotTable::new();
        let options = FetchDocumentsOptions::new(state_dir.clone(), "prefix", "nginx");
        fetch_profile_documents(&s3, &mut table, &options).unwrap();
        assert!(!table.slot_ref(SYNC_SLOT_INDEX).unwrap().in_use());
        let _ = std::fs::remove_dir_all(&state_dir);
    }
}
