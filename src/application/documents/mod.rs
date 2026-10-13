//! **Document loader** — pull catalog-listed S3 keys into document slots.
//! Secret-shaped keys and oversize bodies are refused before they reach a slot.

use zeroize::Zeroizing;

use crate::catalog::ProfileDefinition;
use crate::core::error::Error;
use crate::core::slot::{Slot, SlotError, SlotLease, DOCUMENT_MAX_BYTES};
use crate::legacy::profile::{valid_name, Kind};
use crate::ports::s3::{S3Error, S3Port};

/// Basename used in bundles and slots for an S3 object key (`nginx/site.conf` → `site.conf`).
pub fn document_slot_name(object_key: &str) -> Result<String, Error> {
    let base = object_key
        .rsplit('/')
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| Error::CatalogParse(format!("invalid document key `{object_key}`")))?;
    if !valid_name(base) {
        return Err(Error::InvalidName(base.to_owned()));
    }
    Ok(base.to_owned())
}

/// Keys that belong in SSM or the vault, not on the plain S3 recovery path.
pub fn is_secret_shaped_s3_key(object_key: &str) -> bool {
    let base = object_key.rsplit('/').next().unwrap_or(object_key);
    let lower = base.to_ascii_lowercase();
    if lower.ends_with(".key")
        || lower.ends_with(".pem")
        || lower.ends_with(".p8")
        || lower.ends_with(".age")
    {
        return true;
    }
    const SECRET_MARKERS: &[&str] = &[
        "_secret",
        "_token",
        "_password",
        "private_key",
        "api_key",
        "oauth-private",
    ];
    SECRET_MARKERS.iter().any(|marker| lower.contains(marker))
}

fn object_key_with_prefix(prefix: &str, catalog_key: &str) -> String {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        catalog_key.to_owned()
    } else {
        format!("{prefix}/{catalog_key}")
    }
}

fn reject_secret_shaped_key(object_key: &str) -> Result<(), Error> {
    if is_secret_shaped_s3_key(object_key) {
        tracing::info!(
            target: "host_env_vault::application::documents",
            key = object_key,
            "documents reject secret-shaped s3 key"
        );
        return Err(Error::RuntimeBody);
    }
    Ok(())
}

fn reject_oversize_body(object_key: &str, len: usize) -> Result<(), Error> {
    if len == 0 || len > DOCUMENT_MAX_BYTES {
        tracing::info!(
            target: "host_env_vault::application::documents",
            key = object_key,
            len,
            max = DOCUMENT_MAX_BYTES,
            "documents reject oversize s3 object"
        );
        return Err(Error::RuntimeBody);
    }
    Ok(())
}

/// One pulled document ready to seal or test assertions.
pub struct PulledDocument {
    pub slot_name: String,
    pub bytes: Zeroizing<Vec<u8>>,
}

/// Fetch every catalog document key for a profile from S3.
pub fn pull_profile_documents(
    s3: &dyn S3Port,
    prefix: &str,
    definition: &ProfileDefinition,
) -> Result<Vec<PulledDocument>, Error> {
    let mut pulled = Vec::new();
    for catalog_key in definition.document_keys() {
        reject_secret_shaped_key(catalog_key)?;
        let object_key = object_key_with_prefix(prefix, catalog_key);
        let bytes = s3.get_object(&object_key).map_err(map_s3)?;
        reject_oversize_body(&object_key, bytes.len())?;
        let slot_name = document_slot_name(catalog_key)?;
        tracing::info!(
            target: "host_env_vault::application::documents",
            profile = %definition.name,
            key = catalog_key,
            slot = %slot_name,
            bytes = bytes.len(),
            "documents loaded s3 object"
        );
        pulled.push(PulledDocument {
            slot_name,
            bytes: Zeroizing::new(bytes),
        });
    }
    Ok(pulled)
}

/// Load catalog document keys into an acquired slot (lease must match generation).
pub fn load_documents_into_slot(
    s3: &dyn S3Port,
    prefix: &str,
    definition: &ProfileDefinition,
    slot: &mut Slot,
    lease: SlotLease,
) -> Result<(), Error> {
    for catalog_key in definition.document_keys() {
        reject_secret_shaped_key(catalog_key)?;
        let object_key = object_key_with_prefix(prefix, catalog_key);
        let bytes = s3.get_object(&object_key).map_err(map_s3)?;
        reject_oversize_body(&object_key, bytes.len())?;
        let slot_name = document_slot_name(catalog_key)?;
        slot.put_document(lease, slot_name.as_bytes(), &bytes)
            .map_err(map_slot)?;
        tracing::info!(
            target: "host_env_vault::application::documents",
            profile = %definition.name,
            key = catalog_key,
            slot = %slot_name,
            bytes = bytes.len(),
            "documents loaded s3 object into slot"
        );
    }
    Ok(())
}

/// Map pulled documents into seal entries (file kind).
pub fn seal_entries_from_documents(docs: &[PulledDocument]) -> Vec<crate::catalog::SealEntry<'_>> {
    docs.iter()
        .map(|doc| crate::catalog::SealEntry {
            name: doc.slot_name.clone(),
            kind: Kind::File,
            bytes: &doc.bytes,
        })
        .collect()
}

fn map_s3(err: S3Error) -> Error {
    match err {
        S3Error::NotFound(key) => Error::CatalogParse(format!("s3 object missing: {key}")),
        S3Error::Unavailable => Error::CatalogParse("s3 unavailable".into()),
    }
}

fn map_slot(err: SlotError) -> Error {
    match err {
        SlotError::OversizeName => Error::InvalidName("document name oversize".into()),
        SlotError::OversizeDocument => Error::RuntimeBody,
        SlotError::StaleGeneration => Error::RuntimeBody,
        SlotError::TooManyDocuments => Error::RuntimeBody,
        other => Error::CatalogParse(format!("slot error: {other:?}")),
    }
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod log_tests;

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::catalog::parse_catalog_text;
    use crate::ports::MemoryS3;

    #[test]
    fn missing_s3_object_is_catalog_parse_error() {
        let catalog = parse_catalog_text(
            r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["missing.conf"]}]}"#,
        )
        .unwrap();
        let nginx = catalog.profile("nginx").unwrap();
        let s3 = MemoryS3::new();
        assert!(matches!(
            pull_profile_documents(&s3, "prefix", nginx),
            Err(Error::CatalogParse(_))
        ));
    }

    #[test]
    fn document_slot_name_rejects_empty_basename() {
        assert!(document_slot_name("/").is_err());
    }

    #[test]
    fn nginx_object_key_maps_to_site_conf_slot_name() {
        assert_eq!(
            document_slot_name("nginx/amtgard.conf").unwrap(),
            "amtgard.conf"
        );
    }

    #[test]
    fn empty_s3_object_is_rejected() {
        let catalog = parse_catalog_text(
            r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["empty.conf"]}]}"#,
        )
        .unwrap();
        let nginx = catalog.profile("nginx").unwrap();
        let s3 = MemoryS3::new();
        s3.put("empty.conf", b"");
        assert!(pull_profile_documents(&s3, "", nginx).is_err());
    }

    #[test]
    fn seal_entries_from_documents_maps_file_kind() {
        use super::seal_entries_from_documents;
        let docs = vec![PulledDocument {
            slot_name: "site.conf".into(),
            bytes: Zeroizing::new(b"server {}".to_vec()),
        }];
        let entries = seal_entries_from_documents(&docs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "site.conf");
        assert_eq!(entries[0].kind, Kind::File);
    }

    #[test]
    fn secret_shaped_keys_include_key_material_extensions() {
        assert!(is_secret_shaped_s3_key("teller.key"));
        assert!(is_secret_shaped_s3_key("nginx/oauth-private.key"));
        assert!(!is_secret_shaped_s3_key("nginx/amtgard.conf"));
        assert!(!is_secret_shaped_s3_key("denarius.env"));
        assert!(is_secret_shaped_s3_key("backup_api_key.env"));
        assert!(is_secret_shaped_s3_key("tls.pem"));
        assert!(is_secret_shaped_s3_key("signing.p8"));
        assert!(is_secret_shaped_s3_key("host.age"));
        assert!(is_secret_shaped_s3_key("client_secret.env"));
        assert!(is_secret_shaped_s3_key("db_password.cfg"));
        assert!(is_secret_shaped_s3_key("oauth-private.cfg"));
    }

    #[test]
    fn pull_rejects_each_secret_shaped_catalog_document_key() {
        for key in [
            "vault.pem",
            "oauth-private.key",
            "backup_api_key.env",
            "client_secret.env",
        ] {
            let catalog = parse_catalog_text(&format!(
                r#"{{"profiles":[{{"name":"nginx","inject":[],"runtime":[],"documents":["{key}"]}}]}}"#
            ))
            .unwrap();
            let nginx = catalog.profile("nginx").unwrap();
            let s3 = MemoryS3::new();
            s3.put(key, b"plain-bytes");
            assert!(
                matches!(
                    pull_profile_documents(&s3, "", nginx),
                    Err(Error::RuntimeBody)
                ),
                "expected reject for {key}"
            );
        }
    }
}
