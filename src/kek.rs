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
