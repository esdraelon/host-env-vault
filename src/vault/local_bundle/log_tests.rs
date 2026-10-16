use super::{open_profile_into_slot, seal_profile_in_slot};
use crate::catalog::parse_catalog_text;
use crate::catalog::SealEntry;
use crate::core::slot::SlotTable;
use crate::legacy::profile::Kind;
use crate::testing::log_test_capture::capture_info_logs;
use crate::vault::bundle::{seal_bytes, Entry};
use crate::vault::kek::AgeKek;
use serial_test::serial;
use std::time::Instant;
use zeroize::Zeroizing;

const WEB: &str = r#"{"profiles":[{"name":"app-web","inject":["DB_PASS"],"runtime":[]}]}"#;

#[serial]
#[test]
fn log_local_bundle_seal_from_slot() {
    let catalog = parse_catalog_text(WEB).unwrap();
    let kek = AgeKek::generate();
    let text = capture_info_logs(|| {
        let mut table = SlotTable::new();
        let lease = table.try_acquire(0, Instant::now()).unwrap();
        let slot = table.slot_ref_mut(0).unwrap();
        let entries = vec![SealEntry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: b"x",
        }];
        let _ = seal_profile_in_slot(&catalog, slot, lease, "app-web", &entries, &kek);
    });
    assert!(text.contains("local bundle seal from slot"), "logs: {text}");
}

#[serial]
#[test]
fn log_local_bundle_open_into_slot() {
    let catalog = parse_catalog_text(WEB).unwrap();
    let kek = AgeKek::generate();
    let bundle = seal_bytes(
        "app-web",
        vec![Entry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: Zeroizing::new(b"x".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    let text = capture_info_logs(|| {
        let mut table = SlotTable::new();
        let lease = table.try_acquire(0, Instant::now()).unwrap();
        let slot = table.slot_ref_mut(0).unwrap();
        let _ = open_profile_into_slot(&catalog, &bundle, slot, lease, &kek);
    });
    assert!(text.contains("local bundle open into slot"), "logs: {text}");
}

#[serial]
#[test]
fn log_local_bundle_refuse_open_not_in_catalog() {
    let catalog = parse_catalog_text(WEB).unwrap();
    let kek = AgeKek::generate();
    let bundle = seal_bytes(
        "nginx",
        vec![Entry {
            name: "DB_PASS".into(),
            kind: Kind::Env,
            bytes: Zeroizing::new(b"x".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    let text = capture_info_logs(|| {
        let mut table = SlotTable::new();
        let lease = table.try_acquire(0, Instant::now()).unwrap();
        let slot = table.slot_ref_mut(0).unwrap();
        let _ = open_profile_into_slot(&catalog, &bundle, slot, lease, &kek);
    });
    assert!(
        text.contains("local bundle refuse open not in catalog"),
        "logs: {text}"
    );
}

#[serial]
#[test]
fn log_local_bundle_refuse_open_entry() {
    let catalog = parse_catalog_text(WEB).unwrap();
    let kek = AgeKek::generate();
    let bundle = seal_bytes(
        "app-web",
        vec![Entry {
            name: "APP_KEY".into(),
            kind: Kind::Env,
            bytes: Zeroizing::new(b"k".to_vec()),
        }],
        &kek,
    )
    .unwrap();
    let text = capture_info_logs(|| {
        let mut table = SlotTable::new();
        let lease = table.try_acquire(0, Instant::now()).unwrap();
        let slot = table.slot_ref_mut(0).unwrap();
        let _ = open_profile_into_slot(&catalog, &bundle, slot, lease, &kek);
    });
    assert!(
        text.contains("local bundle refuse open entry"),
        "logs: {text}"
    );
}
