use std::time::Instant;

use crate::application::documents::{load_documents_into_slot, pull_profile_documents};
use crate::catalog::parse_catalog_text;
use crate::core::error::Error;
use crate::core::slot::{SlotTable, DOCUMENT_MAX_BYTES};
use crate::ports::{MemoryS3, S3Port};

const NGINX_CATALOG: &str = r#"{
  "profiles": [{
    "name": "nginx",
    "inject": [],
    "runtime": [],
    "documents": ["nginx/amtgard.conf", "nginx/ork.conf"]
  }]
}"#;

#[test]
fn pull_nginx_site_configs_into_document_slots() {
    let catalog = parse_catalog_text(NGINX_CATALOG).unwrap();
    let nginx = catalog.profile("nginx").unwrap();
    let s3 = MemoryS3::new();
    s3.put("recovery/nginx/amtgard.conf", b"server { listen 443; }");
    s3.put("recovery/nginx/ork.conf", b"server { listen 80; }");
    let docs = pull_profile_documents(&s3, "recovery", nginx).unwrap();
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0].slot_name, "amtgard.conf");
    assert_eq!(&*docs[0].bytes, b"server { listen 443; }");
    assert_eq!(docs[1].slot_name, "ork.conf");
}

#[test]
fn oversize_s3_object_is_rejected_before_slot() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["big.conf"]}]}"#,
    )
    .unwrap();
    let nginx = catalog.profile("nginx").unwrap();
    let s3 = MemoryS3::new();
    let big = vec![b'x'; DOCUMENT_MAX_BYTES + 1];
    s3.put("big.conf", &big);
    assert!(matches!(
        pull_profile_documents(&s3, "", nginx),
        Err(Error::RuntimeBody)
    ));
}

#[test]
fn secret_shaped_s3_key_is_rejected_on_document_path() {
    let catalog = parse_catalog_text(
        r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["teller.key"]}]}"#,
    )
    .unwrap();
    let nginx = catalog.profile("nginx").unwrap();
    let s3 = MemoryS3::new();
    s3.put("teller.key", b"secret-bytes");
    assert!(matches!(
        pull_profile_documents(&s3, "", nginx),
        Err(Error::RuntimeBody)
    ));
    assert!(s3.get_object("teller.key").is_ok());
}

#[test]
fn load_documents_into_slot_sets_profile_and_documents() {
    let catalog = parse_catalog_text(NGINX_CATALOG).unwrap();
    let nginx = catalog.profile("nginx").unwrap();
    let s3 = MemoryS3::new();
    s3.put("recovery/nginx/amtgard.conf", b"server {}");
    s3.put("recovery/nginx/ork.conf", b"server { listen 80; }");
    let mut table = SlotTable::new();
    let lease = table.try_acquire(0, Instant::now()).unwrap();
    let slot = table.slot_ref_mut(0).unwrap();
    slot.set_profile_name(lease, b"nginx").unwrap();
    load_documents_into_slot(&s3, "recovery", nginx, slot, lease).unwrap();
    assert_eq!(slot.document_count(), 2);
    assert_eq!(slot.document_name_bytes(0), Some(b"amtgard.conf".as_ref()));
    table.release(lease).unwrap();
}
