use std::io::Write;
use std::process::{Command, Stdio};

use host_env_vault::ports::{GhError, GhPort};

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessGh;

impl GhPort for ProcessGh {
    fn auth_login_with_token(&self, token: &[u8]) -> Result<(), GhError> {
        let mut child = Command::new("gh")
            .args(["auth", "login", "--hostname", "github.com", "--with-token"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| GhError::Unavailable)?;
        {
            let stdin = child.stdin.as_mut().ok_or(GhError::Unavailable)?;
            stdin.write_all(token).map_err(|_| GhError::Unavailable)?;
            if !token.ends_with(b"\n") {
                stdin.write_all(b"\n").map_err(|_| GhError::Unavailable)?;
            }
        }
        let status = child.wait().map_err(|_| GhError::Unavailable)?;
        if status.success() {
            Ok(())
        } else {
            Err(GhError::LoginFailed)
        }
    }

    fn auth_switch_user(&self, username: &str) -> Result<(), GhError> {
        let status = Command::new("gh")
            .args(["auth", "switch", "--user", username])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| GhError::Unavailable)?;
        if status.success() {
            Ok(())
        } else {
            Err(GhError::SwitchFailed)
        }
    }
}
