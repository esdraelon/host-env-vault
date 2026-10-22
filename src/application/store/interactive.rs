//! TTY prompts for `store` subcommands (not mutation-tested; see `mutants.toml`).

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::core::error::Error;

/// Resolve a flag or prompt on a TTY when interactive.
pub fn resolve_field(
    label: &str,
    flag_value: Option<String>,
    non_interactive: bool,
) -> Result<String, Error> {
    if let Some(value) = flag_value {
        if value.is_empty() {
            return Err(Error::CatalogParse(format!("{label} must not be empty")));
        }
        return Ok(value);
    }
    if non_interactive || !io::stdin().is_terminal() {
        return Err(Error::CatalogParse(format!(
            "missing {label} (pass flag or run on a TTY without --non-interactive)"
        )));
    }
    prompt_line(&format!("{label}: "))
}

/// Resolve a secret value from flag, TTY (hidden), or error in non-interactive mode.
pub fn resolve_secret_value(
    flag_value: Option<String>,
    file_path: Option<PathBuf>,
    non_interactive: bool,
) -> Result<Zeroizing<String>, Error> {
    if let Some(path) = file_path {
        let bytes = std::fs::read(&path).map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                Error::SsmMissing(path.display().to_string())
            } else {
                Error::Io(err)
            }
        })?;
        return Ok(Zeroizing::new(String::from_utf8(bytes).map_err(|err| {
            Error::CatalogParse(format!("secret file is not utf-8: {err}"))
        })?));
    }
    if let Some(value) = flag_value {
        return Ok(Zeroizing::new(value));
    }
    if non_interactive || !io::stdin().is_terminal() {
        return Err(Error::CatalogParse(
            "missing secret value (pass --value, --value-file, or run on a TTY without --non-interactive)".into(),
        ));
    }
    Ok(Zeroizing::new(prompt_secret_hidden("Secret value: ")?))
}

fn prompt_line(prompt: &str) -> Result<String, Error> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(Error::Io)?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(Error::Io)?;
    let line = line.trim_end_matches(['\r', '\n']).to_owned();
    if line.is_empty() {
        return Err(Error::CatalogParse("empty input".into()));
    }
    Ok(line)
}

#[cfg(unix)]
fn prompt_secret_hidden(prompt: &str) -> Result<String, Error> {
    use std::os::fd::AsRawFd;

    eprint!("{prompt}");
    io::stderr().flush().map_err(Error::Io)?;

    let stdin = io::stdin();
    let fd = stdin.as_raw_fd();
    let mut termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
        return Err(Error::CatalogParse("terminal unavailable for hidden input".into()));
    }
    let saved = termios;
    termios.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err(Error::CatalogParse("terminal unavailable for hidden input".into()));
    }
    let mut line = String::new();
    let read_result = io::stdin().read_line(&mut line);
    let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    eprintln!();
    read_result.map_err(Error::Io)?;
    let line = line.trim_end_matches(['\r', '\n']).to_owned();
    if line.is_empty() {
        return Err(Error::CatalogParse("empty secret value".into()));
    }
    Ok(line)
}

#[cfg(not(unix))]
fn prompt_secret_hidden(prompt: &str) -> Result<String, Error> {
    prompt_line(prompt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::Error;

    #[test]
    fn resolve_field_uses_flag_and_rejects_empty_non_interactive() {
        assert_eq!(
            resolve_field("profile", Some("app-web".into()), true).unwrap(),
            "app-web"
        );
        assert!(matches!(
            resolve_field("profile", None, true),
            Err(Error::CatalogParse(_))
        ));
        assert!(matches!(
            resolve_field("profile", Some(String::new()), true),
            Err(Error::CatalogParse(_))
        ));
    }

    #[test]
    fn resolve_secret_value_from_flags_and_files() {
        let dir = std::env::temp_dir().join(format!(
            "hev-store-interactive-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.txt");
        std::fs::write(&path, "from-file").unwrap();
        assert_eq!(
            *resolve_secret_value(Some("inline".into()), None, true).unwrap(),
            "inline"
        );
        assert_eq!(
            *resolve_secret_value(None, Some(path.clone()), true).unwrap(),
            "from-file"
        );
        assert!(matches!(
            resolve_secret_value(None, Some(dir.join("missing.txt")), true),
            Err(Error::SsmMissing(_))
        ));
        assert!(matches!(
            resolve_secret_value(None, None, true),
            Err(Error::CatalogParse(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
