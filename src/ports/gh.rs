//! **Hexagonal port** for the GitHub CLI. Production runs `gh auth`; tests inject
//! [`MemoryGh`].

use std::sync::{Arc, Mutex};

/// Failures talking to `gh`. Messages never include token bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GhError {
    #[error("gh auth login failed")]
    LoginFailed,
    #[error("gh auth switch failed")]
    SwitchFailed,
    #[error("gh unavailable")]
    Unavailable,
}

/// Feed tokens to `gh auth login --with-token` and select the active account.
pub trait GhPort {
    fn auth_login_with_token(&self, token: &[u8]) -> Result<(), GhError>;
    fn auth_switch_user(&self, username: &str) -> Result<(), GhError>;
}

#[derive(Debug, Default)]
struct MemoryGhState {
    login_tokens: Vec<Vec<u8>>,
    switch_user: Option<String>,
    fail_login: bool,
    fail_switch: bool,
}

/// Records stdin passed to login and the user passed to switch (integration tests).
#[derive(Debug, Default, Clone)]
pub struct MemoryGh {
    inner: Arc<Mutex<MemoryGhState>>,
}

impl MemoryGh {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fail_login(&self) {
        self.inner.lock().expect("memory gh lock").fail_login = true;
    }

    pub fn fail_switch(&self) {
        self.inner.lock().expect("memory gh lock").fail_switch = true;
    }

    pub fn login_tokens(&self) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .expect("memory gh lock")
            .login_tokens
            .clone()
    }

    pub fn switch_user(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("memory gh lock")
            .switch_user
            .clone()
    }
}

impl GhPort for MemoryGh {
    fn auth_login_with_token(&self, token: &[u8]) -> Result<(), GhError> {
        let mut state = self.inner.lock().expect("memory gh lock");
        if state.fail_login {
            return Err(GhError::LoginFailed);
        }
        state.login_tokens.push(token.to_vec());
        Ok(())
    }

    fn auth_switch_user(&self, username: &str) -> Result<(), GhError> {
        let mut state = self.inner.lock().expect("memory gh lock");
        if state.fail_switch {
            return Err(GhError::SwitchFailed);
        }
        state.switch_user = Some(username.to_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_gh_fail_login_and_switch() {
        let gh = MemoryGh::new();
        gh.fail_login();
        assert!(matches!(
            gh.auth_login_with_token(b"x"),
            Err(GhError::LoginFailed)
        ));
        let gh = MemoryGh::new();
        gh.fail_switch();
        assert!(matches!(
            gh.auth_switch_user("user"),
            Err(GhError::SwitchFailed)
        ));
    }

    #[test]
    fn memory_gh_records_login_and_switch() {
        let gh = MemoryGh::new();
        gh.auth_login_with_token(b"gho_token_a").unwrap();
        gh.auth_login_with_token(b"gho_token_b").unwrap();
        gh.auth_switch_user("gh-user-alpha").unwrap();
        assert_eq!(
            gh.login_tokens(),
            vec![b"gho_token_a".to_vec(), b"gho_token_b".to_vec()]
        );
        assert_eq!(gh.switch_user().as_deref(), Some("gh-user-alpha"));
    }
}
