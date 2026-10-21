//! M9 guard tests: bounds, wipe, generation, lease expiry, and sync keep-last-bundle.
//! Profile mismatch on render/serve lives in those command integration tests.

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use crate::application::manifest::seed_manifests_for_catalog_text;
    use crate::application::sync::{bundle_path, sync_from_ssm, SyncOptions, SYNC_SLOT_INDEX};
    use crate::catalog::{DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};
    use crate::core::error::Error;
    use crate::core::slot::{
        SlotError, SlotTable, DOCUMENT_MAX_BYTES, LEASE_MS, NAME_MAX_BYTES, SECRET_MAX_BYTES,
    };
    use crate::legacy::profile::Kind;
    use crate::ports::MemorySsm;
    use crate::vault::bundle::{seal_bytes, Entry};
    use crate::vault::kek::AgeKek;
    use zeroize::Zeroizing;

    fn temp_state_dir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("hev-m9-{label}-{}-{id}", std::process::id()))
    }

    #[test]
    fn slot_bounds_wipe_generation_and_lease() {
        let mut table = SlotTable::new();
        let start = Instant::now();
        let lease = table.try_acquire(0, start).unwrap();
        let slot = table.slot_ref_mut(0).unwrap();
        assert_eq!(
            slot.set_profile_name(lease, &vec![b'n'; NAME_MAX_BYTES + 1]),
            Err(SlotError::OversizeName)
        );
        slot.set_profile_name(lease, b"p").unwrap();
        assert_eq!(
            slot.put_secret(lease, b"K", &vec![b'x'; SECRET_MAX_BYTES + 1]),
            Err(SlotError::OversizeSecret)
        );
        assert_eq!(
            slot.put_document(lease, b"d", &vec![b'y'; DOCUMENT_MAX_BYTES + 1]),
            Err(SlotError::OversizeDocument)
        );
        slot.put_secret(lease, b"K", b"v").unwrap();
        table.sweep_expired(start + Duration::from_millis(LEASE_MS));
        assert!(!table.slot_ref(0).unwrap().in_use());
        assert_eq!(table.slot_ref(0).unwrap().generation(), 1);
        let slot = table.slot_ref_mut(0).unwrap();
        assert_eq!(
            slot.put_secret(lease, b"late", b"v"),
            Err(SlotError::StaleGeneration)
        );
    }

    #[test]
    fn sync_keep_last_bundle_when_ssm_pull_fails() {
        let state_dir = temp_state_dir("keep-old");
        let _ = std::fs::remove_dir_all(&state_dir);
        std::fs::create_dir_all(&state_dir).unwrap();
        let kek = AgeKek::generate();
        let stale = seal_bytes(
            "app-web",
            vec![Entry {
                name: "DB_PASS".into(),
                kind: Kind::Env,
                bytes: Zeroizing::new(b"stale-secret".to_vec()),
            }],
            &kek,
        )
        .unwrap();
        let bundle_file = bundle_path(&state_dir, "app-web");
        std::fs::write(&bundle_file, &stale).unwrap();

        let catalog = r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#;
        seed_manifests_for_catalog_text(&state_dir, catalog).unwrap();
        let ssm = MemorySsm::new();
        ssm.put(DEFAULT_CATALOG_PARAMETER, catalog);

        let mut table = SlotTable::new();
        let options = SyncOptions {
            identity_path: state_dir.join("kek.age"),
            state_dir: state_dir.clone(),
            catalog_param: DEFAULT_CATALOG_PARAMETER.to_owned(),
            secrets_prefix: DEFAULT_SECRETS_PREFIX.to_owned(),
            source: crate::config::SyncSourceKind::Ssm,
            local_secrets_dir: None,
            manifests_dir: None,
            s3_prefix: None,
        };
        assert!(matches!(
            sync_from_ssm(&ssm, &kek, &mut table, &options),
            Err(Error::SyncFailed { count: 1 })
        ));
        assert_eq!(std::fs::read(&bundle_file).unwrap(), stale);
        assert!(!table.slot_ref(SYNC_SLOT_INDEX).unwrap().in_use());
        let _ = std::fs::remove_dir_all(&state_dir);
    }
}
