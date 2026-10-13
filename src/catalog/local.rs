//! Local catalog snapshot beside sealed bundles. Sync writes it; render reads it
//! without calling SSM.

use std::path::{Path, PathBuf};

use crate::catalog::parse::{parse_catalog_text, Catalog};
use crate::core::error::Error;

/// Filename under `state_dir` for the last synced catalog document.
pub const CATALOG_SNAPSHOT_FILE: &str = "catalog.json";

pub fn catalog_snapshot_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CATALOG_SNAPSHOT_FILE)
}

/// Parse the catalog snapshot written by sync.
pub fn load_catalog_snapshot(state_dir: &Path) -> Result<Catalog, Error> {
    let path = catalog_snapshot_path(state_dir);
    let text = std::fs::read_to_string(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            Error::CatalogParse(format!(
                "missing catalog snapshot `{}` (run sync first)",
                path.display()
            ))
        } else {
            Error::Io(err)
        }
    })?;
    parse_catalog_text(&text)
}

/// Persist raw catalog JSON or TOML from SSM. Render uses the same bytes sync saw.
pub fn write_catalog_snapshot(state_dir: &Path, catalog_text: &str) -> Result<(), Error> {
    std::fs::create_dir_all(state_dir)?;
    let path = catalog_snapshot_path(state_dir);
    write_atomically(&path, catalog_text.as_bytes())
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::DEFAULT_CATALOG_PARAMETER;

    const SAMPLE: &str =
        r#"{"profiles":[{"name":"denarius-web","inject":["DB_PASS"],"runtime":[]}]}"#;

    fn temp_dir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "hev-catalog-local-{label}-{}-{id}",
            std::process::id()
        ))
    }

    #[test]
    fn snapshot_round_trips_through_parse() {
        let dir = temp_dir("round-trip");
        let _ = std::fs::remove_dir_all(&dir);
        write_catalog_snapshot(&dir, SAMPLE).unwrap();
        assert_eq!(catalog_snapshot_path(&dir), dir.join(CATALOG_SNAPSHOT_FILE));
        let catalog = load_catalog_snapshot(&dir).unwrap();
        assert!(catalog.profile("denarius-web").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_snapshot_is_actionable_error() {
        let dir = temp_dir("missing");
        let _ = std::fs::remove_dir_all(&dir);
        match load_catalog_snapshot(&dir) {
            Err(crate::core::error::Error::CatalogParse(message)) => {
                assert!(message.contains("run sync first"));
            }
            other => panic!("expected catalog parse hint, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_creates_nested_state_directory() {
        let dir = temp_dir("nested-state");
        let _ = std::fs::remove_dir_all(&dir);
        let state = dir.join("deep/vault/state");
        write_catalog_snapshot(&state, SAMPLE).unwrap();
        assert!(catalog_snapshot_path(&state).is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_can_write_with_empty_parent_component() {
        let work = temp_dir("solo-file");
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(&work).unwrap();
        write_atomically(std::path::Path::new("solo-catalog.json"), SAMPLE.as_bytes()).unwrap();
        assert!(work.join("solo-catalog.json").is_file());
        std::env::set_current_dir(previous).unwrap();
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn default_catalog_parameter_is_documented_in_plan() {
        assert_eq!(DEFAULT_CATALOG_PARAMETER, "/host-env-vault/profiles");
    }
}
