use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::core::error::Error;
use crate::legacy::profile::Kind;
use crate::vault::bundle::Entry;

/// How rendered files are owned.
///
/// With no gid, the directory is `0700` and files are `0400`, owned by the
/// rendering user. That matches today's images, which run as root.
///
/// With a gid, the directory is `0550` root:gid and files are `0440` root:gid.
/// The container user is in that group and can read. It does not own the
/// directory, so a read-write mount still cannot add files. Pass the gid that
/// `www-data` will have once the images set `USER`.
#[derive(Debug, Clone, Copy)]
pub struct RenderMode {
    pub dir_mode: u32,
    pub file_mode: u32,
    pub chown_uid: Option<u32>,
    pub chown_gid: Option<u32>,
}

impl RenderMode {
    pub fn from_gid(gid: Option<u32>) -> Self {
        match gid {
            None => Self {
                dir_mode: 0o700,
                file_mode: 0o400,
                chown_uid: None,
                chown_gid: None,
            },
            Some(gid) => Self {
                dir_mode: 0o550,
                file_mode: 0o440,
                chown_uid: Some(0),
                chown_gid: Some(gid),
            },
        }
    }
}

/// Write `entries` into an empty `dest`. Secret material is files, not process
/// environment, so `docker inspect` does not list the values.
pub fn render(dest: &Path, entries: &[Entry], mode: RenderMode) -> Result<(), Error> {
    if dest.exists() {
        if !dest.is_dir() || fs::read_dir(dest)?.next().is_some() {
            return Err(Error::DestNotEmpty(dest.to_path_buf()));
        }
    } else {
        fs::create_dir(dest)?;
    }
    set_mode(dest, 0o700)?;

    let mut env_lines: Vec<(&str, &[u8])> = entries
        .iter()
        .filter(|entry| entry.kind == Kind::Env)
        .map(|entry| (entry.name.as_str(), entry.bytes.as_slice()))
        .collect();
    env_lines.sort_by_key(|(name, _)| *name);

    if !env_lines.is_empty() {
        let path = dest.join("secrets.env");
        write_secret(&path, &render_env(&env_lines), mode)?;
    }

    let files: Vec<_> = entries
        .iter()
        .filter(|entry| entry.kind == Kind::File)
        .collect();
    if !files.is_empty() {
        let files_dir = dest.join("files");
        fs::create_dir(&files_dir)?;
        set_mode(&files_dir, mode.dir_mode)?;
        apply_owner(&files_dir, mode)?;
        for entry in files {
            write_secret(&files_dir.join(&entry.name), &entry.bytes, mode)?;
        }
    }

    set_mode(dest, mode.dir_mode)?;
    apply_owner(dest, mode)?;
    Ok(())
}

fn render_env(lines: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in lines {
        out.extend_from_slice(name.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(b'\n');
    }
    out
}

fn write_secret(path: &Path, bytes: &[u8], mode: RenderMode) -> Result<(), Error> {
    let tmp = path.with_extension("partial");
    {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    set_mode(&tmp, mode.file_mode)?;
    apply_owner(&tmp, mode)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), Error> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn apply_owner(path: &Path, mode: RenderMode) -> Result<(), Error> {
    if mode.chown_uid.is_none() && mode.chown_gid.is_none() {
        return Ok(());
    }
    use std::os::unix::fs::chown;
    chown(path, mode.chown_uid, mode.chown_gid)?;
    Ok(())
}

/// Read a staging directory: `secrets.env` plus optional `files/`.
pub fn read_staging(dir: &Path) -> Result<Vec<Entry>, Error> {
    use zeroize::Zeroizing;

    let mut entries = Vec::new();
    let env_path = dir.join("secrets.env");
    if env_path.exists() {
        let text = fs::read_to_string(&env_path)?;
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line.split_once('=').ok_or_else(|| {
                Error::InvalidEnvValue(format!("{}:{}", env_path.display(), index + 1))
            })?;
            entries.push(Entry {
                name: name.to_owned(),
                kind: Kind::Env,
                bytes: Zeroizing::new(value.as_bytes().to_vec()),
            });
        }
    }
    let files_dir = dir.join("files");
    if files_dir.exists() {
        let mut names = Vec::new();
        for item in fs::read_dir(&files_dir)? {
            let item = item?;
            if item.file_type()?.is_file() {
                names.push(item.path());
            }
        }
        names.sort();
        for path in names {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| Error::InvalidName(path.display().to_string()))?
                .to_owned();
            let bytes = Zeroizing::new(fs::read(&path)?);
            entries.push(Entry {
                name,
                kind: Kind::File,
                bytes,
            });
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn entry(kind: Kind, name: &str, value: &str) -> Entry {
        Entry {
            name: name.to_owned(),
            kind,
            bytes: Zeroizing::new(value.as_bytes().to_vec()),
        }
    }

    fn scratch() -> std::path::PathBuf {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("hev-render-{}", hex(&nonce)));
        fs::create_dir(&path).unwrap();
        path
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn render_writes_readonly_files_and_refuses_a_dirty_dest() {
        let dest = scratch();
        render(
            &dest,
            &[
                entry(Kind::Env, "DB_PASS", "s3cret"),
                entry(Kind::File, "client.key", "key-bytes"),
            ],
            RenderMode::from_gid(None),
        )
        .unwrap();
        assert_eq!(mode_of(&dest), 0o700);
        assert_eq!(mode_of(&dest.join("secrets.env")), 0o400);
        assert_eq!(mode_of(&dest.join("files").join("client.key")), 0o400);
        let env = fs::read_to_string(dest.join("secrets.env")).unwrap();
        assert_eq!(env, "DB_PASS=s3cret\n");
        assert!(render(
            &dest,
            &[entry(Kind::Env, "DB_PASS", "x")],
            RenderMode::from_gid(None)
        )
        .is_err());
        fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn grouped_render_is_root_owned_and_group_readable() {
        let mode = RenderMode::from_gid(Some(33));
        assert_eq!(mode.dir_mode, 0o550);
        assert_eq!(mode.file_mode, 0o440);
        assert_eq!(mode.chown_uid, Some(0));
        assert_eq!(mode.chown_gid, Some(33));
    }

    #[test]
    fn render_creates_dest_and_read_staging_round_trips() {
        let dest = scratch();
        render(
            &dest,
            &[
                entry(Kind::Env, "DB_PASS", "pw"),
                entry(Kind::File, "client.key", "pem"),
            ],
            RenderMode::from_gid(None),
        )
        .unwrap();
        let entries = read_staging(&dest).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "DB_PASS");
        assert_eq!(&entries[0].bytes[..], b"pw");
        assert_eq!(entries[1].name, "client.key");
        fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn read_staging_skips_comments_and_rejects_bad_env_lines() {
        let dest = scratch();
        fs::write(dest.join("secrets.env"), "# comment\n\nBADLINE\n").unwrap();
        assert!(read_staging(&dest).is_err());
        fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn render_refuses_non_directory_dest() {
        let dest = scratch();
        let file = dest.join("not-dir");
        fs::write(&file, b"x").unwrap();
        assert!(render(&file, &[], RenderMode::from_gid(None)).is_err());
        fs::remove_dir_all(dest).unwrap();
    }
}
