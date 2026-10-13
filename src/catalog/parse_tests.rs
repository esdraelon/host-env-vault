use super::parse::{parse_catalog_text, valid_s3_document_key, Catalog, ProfileDefinition};
use crate::error::Error;
use crate::profile::Kind;

#[test]
fn empty_document_is_rejected() {
    assert!(matches!(
        parse_catalog_text("   "),
        Err(Error::CatalogParse(_))
    ));
}

#[test]
fn duplicate_profile_names_are_rejected() {
    let text = r#"{"profiles":[
      {"name":"a","inject":[],"runtime":[]},
      {"name":"a","inject":[],"runtime":[]}
    ]}"#;
    assert!(matches!(
        parse_catalog_text(text),
        Err(Error::CatalogParse(_))
    ));
}

#[test]
fn invalid_profile_name_is_rejected() {
    let text = r#"{"profiles":[{"name":"../bad","inject":[],"runtime":[]}]}"#;
    assert!(matches!(
        parse_catalog_text(text),
        Err(Error::CatalogParse(_))
    ));
}

#[test]
fn invalid_inject_name_is_rejected() {
    let text = r#"{"profiles":[{"name":"nginx","inject":["bad/name"],"runtime":[]}]}"#;
    assert!(matches!(
        parse_catalog_text(text),
        Err(Error::CatalogParse(_))
    ));
}

#[test]
fn socket_profile_requires_peer_uid() {
    let text = r#"{"profiles":[{"name":"worker","inject":[],"runtime":[],"socket":true}]}"#;
    assert!(matches!(
        parse_catalog_text(text),
        Err(Error::CatalogParse(_))
    ));
}

#[test]
#[test]
fn valid_s3_document_key_rejects_traversal() {
    assert!(!valid_s3_document_key("../x"));
    assert!(valid_s3_document_key("nginx/site.conf"));
}

#[test]
fn invalid_document_s3_key_is_rejected() {
    let text = r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["../escape.conf"]}]}"#;
    assert!(matches!(
        parse_catalog_text(text),
        Err(Error::CatalogParse(_))
    ));
}

#[test]
fn nginx_document_key_allows_slashes() {
    let text = r#"{"profiles":[{"name":"nginx","inject":[],"runtime":[],"documents":["nginx/site.conf"]}]}"#;
    let catalog = parse_catalog_text(text).unwrap();
    let nginx = catalog.profile("nginx").unwrap();
    assert!(nginx.allows_document_slot("site.conf"));
    assert!(nginx.allows_seal(Kind::File, "site.conf"));
    assert!(!nginx.allows_document_slot("other.conf"));
    assert!(!nginx.allows_seal(Kind::File, "other.conf"));
    assert!(!nginx.allows_seal(Kind::Env, "site.conf"));
}

#[test]
fn catalog_profile_lookup_and_builder() {
    let def = ProfileDefinition::new(
        "custom",
        vec!["A".into()],
        vec![],
        vec![],
        vec![],
        false,
        None,
        None,
        None,
        vec!["doc.conf".into()],
    );
    let catalog = Catalog::from_profiles(vec![def]).unwrap();
    assert_eq!(catalog.profile_names().count(), 1);
    let p = catalog.profile("custom").unwrap();
    assert_eq!(p.documents, vec!["doc.conf"]);
    assert!(p.allows_seal(Kind::Env, "A"));
}
