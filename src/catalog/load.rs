use crate::catalog::parse::{parse_catalog_text, Catalog, ProfileDefinition};
use crate::catalog::DEFAULT_CATALOG_PARAMETER;
use crate::error::Error;
use crate::port::ssm::{SsmError, SsmPort};
use crate::slot::{Slot, SlotError, SlotLease};

/// Fetch and parse the catalog parameter from SSM.
pub fn load_catalog_from_ssm(
    ssm: &dyn SsmPort,
    parameter_name: &str,
) -> Result<Catalog, Error> {
    let text = ssm.get_parameter(parameter_name).map_err(map_ssm)?;
    parse_catalog_text(&text)
}

fn map_ssm(err: SsmError) -> Error {
    match err {
        SsmError::NotFound(name) => Error::SsmMissing(name),
        SsmError::Unavailable => Error::CatalogParse("ssm unavailable".into()),
    }
}

/// Bind a catalog profile to a slot: set the profile name from the allowlist.
/// Secret and document payloads are filled later by sync; this loads metadata only.
pub fn bind_catalog_profile<'a>(
    catalog: &'a Catalog,
    profile_name: &str,
    slot: &mut Slot,
    lease: SlotLease,
) -> Result<&'a ProfileDefinition, Error> {
    let definition = catalog
        .profile(profile_name)
        .ok_or_else(|| Error::NotInCatalog(profile_name.to_owned()))?;
    slot.set_profile_name(lease, definition.name.as_bytes())
        .map_err(map_slot)?;
    Ok(definition)
}

fn map_slot(err: SlotError) -> Error {
    match err {
        SlotError::OversizeName => Error::InvalidName("profile name oversize".into()),
        SlotError::StaleGeneration => Error::RuntimeBody,
        other => Error::CatalogParse(format!("slot error: {other:?}")),
    }
}

/// Convenience for the default catalog parameter path from the plan.
pub fn load_default_catalog(ssm: &dyn SsmPort) -> Result<Catalog, Error> {
    load_catalog_from_ssm(ssm, DEFAULT_CATALOG_PARAMETER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::ssm::MemorySsm;
    use crate::slot::SlotTable;
    use std::time::Instant;

    const SAMPLE: &str = r#"{
      "profiles": [{
        "name": "denarius-web",
        "inject": ["DB_PASS"],
        "runtime": [],
        "socket": false
      }]
    }"#;

    #[test]
    fn load_from_memory_ssm_and_bind_slot() {
        let ssm = MemorySsm::new();
        ssm.put(DEFAULT_CATALOG_PARAMETER, SAMPLE);
        let catalog = load_default_catalog(&ssm).unwrap();
        assert!(catalog.profile("denarius-web").is_some());
        let catalog = load_catalog_from_ssm(&ssm, DEFAULT_CATALOG_PARAMETER).unwrap();
        let mut table = SlotTable::new();
        let lease = table.try_acquire(0, Instant::now()).unwrap();
        let slot = table.slot_ref_mut(0).unwrap();
        let def = bind_catalog_profile(&catalog, "denarius-web", slot, lease).unwrap();
        assert_eq!(def.name, "denarius-web");
        assert_eq!(slot.profile_name_bytes(), b"denarius-web");
    }
}
