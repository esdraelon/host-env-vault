//! SQLite profile store sealed as one age-encrypted file (`{profile}.secrets.db`).

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::core::error::Error;
use crate::vault::kek::AgeKek;

use super::{set_mode, PROFILE_SQLITE_SUFFIX};

const ENTRY_KIND_ENV: &str = "env";

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS entries (
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (name, kind)
);";

/// Path to the SQLite encrypted store blob for one profile.
pub fn sqlite_store_path(store_dir: &Path, profile: &str) -> PathBuf {
    store_dir.join(format!("{profile}{PROFILE_SQLITE_SUFFIX}"))
}

/// Write entries into a sealed SQLite store file.
pub fn write_sqlite_profile_store(
    store_dir: &Path,
    profile: &str,
    entries: &HashMap<String, String>,
    kek: &AgeKek,
) -> Result<(), Error> {
    if !store_dir.as_os_str().is_empty() {
        fs::create_dir_all(store_dir)?;
    }
    let db_bytes = build_sqlite_bytes(entries)?;
    let sealed = kek.seal_plaintext(&db_bytes)?;
    let path = sqlite_store_path(store_dir, profile);
    let tmp = store_dir.join(format!("{profile}{PROFILE_SQLITE_SUFFIX}.tmp"));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(&sealed)?;
    }
    set_mode(&tmp, 0o600)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Read and decrypt one SQLite profile store file.
pub fn read_sqlite_profile_store(
    store_dir: &Path,
    profile: &str,
    kek: &AgeKek,
) -> Result<HashMap<String, String>, Error> {
    let path = sqlite_store_path(store_dir, profile);
    let sealed = fs::read(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            Error::SsmMissing(path.display().to_string())
        } else {
            Error::Io(err)
        }
    })?;
    let plain = kek.open_sealed(&sealed)?;
    load_entries_from_sqlite_bytes(&plain).map_err(|err| {
        Error::CatalogParse(format!(
            "host store sqlite decode {}: {err}",
            path.display()
        ))
    })
}

fn build_sqlite_bytes(entries: &HashMap<String, String>) -> Result<Vec<u8>, Error> {
    let tmp = temp_sqlite_path("build");
    let _ = fs::remove_file(&tmp);
    {
        let conn = Connection::open(&tmp).map_err(sqlite_err)?;
        conn.execute_batch(SCHEMA).map_err(sqlite_err)?;
        for (name, value) in entries {
            conn.execute(
                "INSERT INTO entries (name, kind, value) VALUES (?1, ?2, ?3)",
                params![name, ENTRY_KIND_ENV, value],
            )
            .map_err(sqlite_err)?;
        }
    }
    let bytes = fs::read(&tmp).map_err(Error::Io)?;
    let _ = fs::remove_file(&tmp);
    Ok(bytes)
}

fn load_entries_from_sqlite_bytes(bytes: &[u8]) -> Result<HashMap<String, String>, Error> {
    let conn = open_connection_from_bytes(bytes)?;
    let mut stmt = conn
        .prepare("SELECT name, kind, value FROM entries ORDER BY name, kind")
        .map_err(sqlite_err)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sqlite_err)?;
    let mut out = HashMap::new();
    for row in rows {
        let (name, kind, value) = row.map_err(sqlite_err)?;
        let key = if kind == ENTRY_KIND_ENV {
            name
        } else {
            format!("{name}:{kind}")
        };
        out.insert(key, value);
    }
    Ok(out)
}

fn open_connection_from_bytes(bytes: &[u8]) -> Result<Connection, Error> {
    let tmp = temp_sqlite_path("open");
    let _ = fs::remove_file(&tmp);
    fs::write(&tmp, bytes).map_err(Error::Io)?;
    let conn = Connection::open(&tmp).map_err(sqlite_err)?;
    let _ = fs::remove_file(&tmp);
    Ok(conn)
}

fn temp_sqlite_path(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hev-host-store-sqlite-{label}-{}-{id}.db",
        std::process::id()
    ))
}

fn sqlite_err(err: rusqlite::Error) -> Error {
    Error::CatalogParse(format!("host store sqlite: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::kek::AgeKek;

    #[test]
    fn read_sqlite_maps_missing_file_to_ssm_missing() {
        let root = std::env::temp_dir().join(format!(
            "hev-sqlite-read-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let kek = AgeKek::generate();
        assert!(matches!(
            read_sqlite_profile_store(&root, "app-worker", &kek),
            Err(Error::SsmMissing(path)) if path.contains("app-worker.secrets.db")
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sqlite_store_round_trip_in_memory_schema() {
        let mut entries = HashMap::new();
        entries.insert("DB_PASS".into(), "secret".into());
        let bytes = build_sqlite_bytes(&entries).unwrap();
        let back = load_entries_from_sqlite_bytes(&bytes).unwrap();
        assert_eq!(back, entries);
    }
}
