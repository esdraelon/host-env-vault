use std::fs::{self, OpenOptions};
use std::path::Path;

use age::secrecy::ExposeSecret;
use age::x25519::Identity;

use crate::error::Error;

/// Age identity used as the KEK. The trait-shaped wrap/unwrap is the seam a
/// cloud KMS provider replaces later. Profiles do not change when it does.
pub struct AgeKek {
    identity: Identity,
}

impl AgeKek {
    pub fn generate() -> Self {
        Self {
            identity: Identity::generate(),
        }
    }

    pub fn recipient_line(&self) -> String {
        self.identity.to_public().to_string()
    }

    pub fn write_identity(&self, path: &Path) -> Result<(), Error> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let secret = Identity::to_string(&self.identity);
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        {
            use std::io::Write;
            writeln!(
                file,
                "# host-env-vault KEK. Root-only. Keep out of bundle backups."
            )?;
            writeln!(file, "{}", secret.expose_secret())?;
        }
        set_mode(path, 0o400)?;
        Ok(())
    }

    pub fn read_identity(path: &Path) -> Result<Self, Error> {
        let mut text = fs::read_to_string(path)?;
        let line = text
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("AGE-SECRET-KEY-1"))
            .ok_or(Error::Identity)?
            .to_owned();
        zeroize_string(&mut text);
        let identity: Identity = line.parse().map_err(|_| Error::Identity)?;
        Ok(Self { identity })
    }

    pub fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let recipient = self.identity.to_public();
        age::encrypt(&recipient, dek).map_err(|_| Error::Kek)
    }

    pub fn unwrap_dek(&self, wrapped: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, Error> {
        let mut plain = age::decrypt(&self.identity, wrapped).map_err(|_| Error::Kek)?;
        if plain.len() != 32 {
            zeroize::Zeroize::zeroize(plain.as_mut_slice());
            return Err(Error::Kek);
        }
        let mut dek = zeroize::Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(&plain);
        zeroize::Zeroize::zeroize(plain.as_mut_slice());
        Ok(dek)
    }
}

fn zeroize_string(text: &mut String) {
    use zeroize::Zeroize;
    text.zeroize();
}

fn set_mode(path: &Path, mode: u32) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn wrap_unwrap_round_trip() {
        let kek = AgeKek::generate();
        let dek = [7u8; 32];
        let wrapped = kek.wrap_dek(&dek).unwrap();
        let back = kek.unwrap_dek(&wrapped).unwrap();
        assert_eq!(&*back, &dek);
    }

    #[test]
    fn unwrap_rejects_invalid_or_short_plaintext() {
        let kek = AgeKek::generate();
        assert!(matches!(kek.unwrap_dek(b"not-valid-age"), Err(Error::Kek)));
        let dek = [9u8; 32];
        let wrapped = kek.wrap_dek(&dek).unwrap();
        let other = AgeKek::generate();
        assert!(matches!(other.unwrap_dek(&wrapped), Err(Error::Kek)));
    }

    #[test]
    fn write_and_read_identity_round_trip() {
        let kek = AgeKek::generate();
        let line = kek.recipient_line();
        assert!(line.starts_with("age1"));
        let dir = std::env::temp_dir().join(format!("hev-kek-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let path = dir.join("kek.age");
        kek.write_identity(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400);
        let loaded = AgeKek::read_identity(&path).unwrap();
        let dek = [1u8; 32];
        let wrapped = loaded.wrap_dek(&dek).unwrap();
        assert_eq!(&*kek.unwrap_dek(&wrapped).unwrap(), &dek);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn read_identity_rejects_missing_secret_line() {
        let dir = std::env::temp_dir().join(format!("hev-kek-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let path = dir.join("bad.age");
        fs::write(&path, "# no secret here\n").unwrap();
        assert!(matches!(AgeKek::read_identity(&path), Err(Error::Identity)));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_identity_creates_parent_directory() {
        let kek = AgeKek::generate();
        let dir = std::env::temp_dir().join(format!("hev-kek-nested-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("kek.age");
        kek.write_identity(&path).unwrap();
        assert!(path.is_file());
        fs::remove_dir_all(dir).unwrap();
    }
}
