use super::{open_profile_into_slot, seal_profile_in_slot};
use crate::catalog::parse_catalog_text;
use crate::catalog::SealEntry;
use crate::error::Error;
use crate::kek::AgeKek;
use crate::profile::Kind;
use crate::slot::SlotTable;
use std::time::Instant;

const WORKER_CATALOG: &str = r#"{
  "profiles": [{
    "name": "denarius-worker",
    "inject": ["DB_PASS", "STRIPE_WEBHOOK_SECRET"],
    "runtime": ["APP_KEY", "STRIPE_SECRET_KEY"],
    "runtime_files": ["teller.key"],
    "socket": true,
    "require_uid": 33
  }]
}"#;

fn worker_entries() -> Vec<SealEntry<'static>> {
    vec![
        SealEntry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: b"db-secret",
        },
        SealEntry {
            name: "STRIPE_WEBHOOK_SECRET".into(),
            kind: Kind::Env,
            bytes: b"whsec",
        },
    ]
}

#[test]
fn seal_and_open_round_trip_through_one_slot() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    let bundle =
        seal_profile_in_slot(&catalog, slot, lease, "denarius-worker", &worker_entries(), &kek)
            .unwrap();
    table.release(lease).unwrap();

    let lease2 = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    let opened = open_profile_into_slot(&catalog, &bundle, slot, lease2, &kek).unwrap();
    assert_eq!(opened.profile, "denarius-worker");
    assert_eq!(slot.profile_name_bytes(), b"denarius-worker");
    assert_eq!(slot.secret_count(), 2);
    assert_eq!(slot.secret_bytes(0), Some(&b"db-secret"[..]));
    table.release(lease2).unwrap();
}

#[test]
fn duplicate_seal_entry_names_are_refused() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    let entries = vec![
        SealEntry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: b"one",
        },
        SealEntry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: b"two",
        },
    ];
    assert!(matches!(
        seal_profile_in_slot(&catalog, slot, lease, "denarius-worker", &entries, &kek),
        Err(Error::DuplicateEntry(_))
    ));
}

#[test]
fn open_refuses_profile_missing_from_catalog() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let kek = AgeKek::generate();
    let bundle = crate::seal_bytes(
        "nginx",
        vec![crate::Entry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: zeroize::Zeroizing::new(b"x".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    let mut table = SlotTable::new();
    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    assert!(matches!(
        open_profile_into_slot(&catalog, &bundle, slot, lease, &kek),
        Err(Error::NotInCatalog(_))
    ));
}

#[test]
fn open_refuses_entry_outside_catalog_allowlist() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let kek = AgeKek::generate();
    let bundle = crate::seal_bytes(
        "denarius-worker",
        vec![crate::Entry {
            name: "STRIPE_PUBLISHABLE_KEY".into(),
            kind: Kind::Env,
            bytes: zeroize::Zeroizing::new(b"pk".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    let mut table = SlotTable::new();
    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    assert!(matches!(
        open_profile_into_slot(&catalog, &bundle, slot, lease, &kek),
        Err(Error::EntryNotAllowed { .. })
    ));
}

#[test]
fn seal_and_open_includes_runtime_file_in_slot() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    let entries = vec![SealEntry {
        name: "teller.key".into(),
        kind: Kind::File,
        bytes: b"-----BEGIN KEY-----",
    }];
    let bundle =
        seal_profile_in_slot(&catalog, slot, lease, "denarius-worker", &entries, &kek).unwrap();
    table.release(lease).unwrap();
    let lease2 = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    open_profile_into_slot(&catalog, &bundle, slot, lease2, &kek).unwrap();
    assert_eq!(slot.document_count(), 1);
    assert_eq!(slot.document_bytes(0), Some(&b"-----BEGIN KEY-----"[..]));
    table.release(lease2).unwrap();
}

#[test]
fn catalog_refuses_disallowed_entry_on_seal() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    let entries = vec![SealEntry {
        name: "STRIPE_PUBLISHABLE_KEY".into(),
        kind: Kind::Env,
        bytes: b"pk",
    }];
    let err =
        seal_profile_in_slot(&catalog, slot, lease, "denarius-worker", &entries, &kek).unwrap_err();
    assert!(matches!(err, Error::EntryNotAllowed { .. }));
}

#[test]
fn relabeled_header_does_not_open_into_slot() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    let mut bundle =
        seal_profile_in_slot(&catalog, slot, lease, "denarius-worker", &worker_entries(), &kek)
            .unwrap();
    table.release(lease).unwrap();

    let worker = b"denarius-worker";
    let relabeled = b"denarius-webabr";
    assert_eq!(worker.len(), relabeled.len());
    let at = bundle
        .windows(worker.len())
        .position(|window| window == worker)
        .unwrap();
    bundle[at..at + relabeled.len()].copy_from_slice(relabeled);

    let lease2 = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    assert!(matches!(
        open_profile_into_slot(&catalog, &bundle, slot, lease2, &kek),
        Err(Error::BundleAuth)
    ));
}

#[test]
fn tampered_ciphertext_does_not_open_into_slot() {
    let catalog = parse_catalog_text(WORKER_CATALOG).unwrap();
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();
    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    let mut bundle =
        seal_profile_in_slot(&catalog, slot, lease, "denarius-worker", &worker_entries(), &kek)
            .unwrap();
    table.release(lease).unwrap();
    let last = bundle.len() - 1;
    bundle[last] ^= 0xff;

    let lease2 = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    assert!(matches!(
        open_profile_into_slot(&catalog, &bundle, slot, lease2, &kek),
        Err(Error::BundleAuth)
    ));
}

#[test]
fn only_one_profile_occupies_slot_between_seals() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[
          {"name":"denarius-web","inject":["DB_PASS"],"runtime":[]},
          {"name":"denarius-connect","inject":["STRIPE_SECRET_KEY"],"runtime":[]}
        ]}"#,
    )
    .unwrap();
    let kek = AgeKek::generate();
    let mut table = SlotTable::new();

    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    let _ = seal_profile_in_slot(
        &catalog,
        slot,
        lease,
        "denarius-web",
        &[SealEntry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: b"web",
        }],
        &kek,
    )
    .unwrap();
    table.release(lease).unwrap();

    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    let bundle = seal_profile_in_slot(
        &catalog,
        slot,
        lease,
        "denarius-connect",
        &[SealEntry {
            name: "STRIPE_SECRET_KEY".into(),
            kind: Kind::Env,
            bytes: b"sk",
        }],
        &kek,
    )
    .unwrap();
    table.release(lease).unwrap();

    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    open_profile_into_slot(&catalog, &bundle, slot, lease, &kek).unwrap();
    assert_eq!(slot.profile_name_bytes(), b"denarius-connect");
    assert_eq!(slot.secret_count(), 1);
    table.release(lease).unwrap();
}
