use crate::core::error::Error;

/// A security personality. The name is the only selector. Callers never pass a
/// second profile inside a bundle or a socket frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileId {
    AppWeb,
    AppWorker,
    EdgeProxy,
    ApiHttp,
    ApiWorker,
}

pub const ALL: [ProfileId; 5] = [
    ProfileId::AppWeb,
    ProfileId::AppWorker,
    ProfileId::EdgeProxy,
    ProfileId::ApiHttp,
    ProfileId::ApiWorker,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Env,
    File,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Env => "env",
            Kind::File => "file",
        }
    }

    pub(crate) fn tag(self) -> u8 {
        match self {
            Kind::Env => 1,
            Kind::File => 2,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Kind::Env),
            2 => Some(Kind::File),
            _ => None,
        }
    }
}

/// Allowlist for one legacy spike profile. `provisional` marks names that may
/// still move when processes are traced. Seal still refuses names outside the list.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub provisional: bool,
    /// When true, `serve` holds this profile's data key and exposes key wrap
    /// on a unix socket. It does not retain the sealed env or files.
    pub runtime_key_wrap: bool,
    env: &'static [&'static str],
    files: &'static [&'static str],
}

impl ProfileId {
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileId::AppWeb => "app-web",
            ProfileId::AppWorker => "app-worker",
            ProfileId::EdgeProxy => "edge-proxy",
            ProfileId::ApiHttp => "api-http",
            ProfileId::ApiWorker => "api-worker",
        }
    }

    pub fn parse(name: &str) -> Result<Self, Error> {
        ALL.into_iter()
            .find(|profile| profile.as_str() == name)
            .ok_or_else(|| Error::UnknownProfile(name.to_owned()))
    }

    pub fn policy(self) -> Policy {
        match self {
            ProfileId::AppWeb => Policy {
                provisional: false,
                runtime_key_wrap: false,
                env: &["DB_PASS", "SESSION_SECRET", "OAUTH_CLIENT_SECRET"],
                files: &[],
            },
            ProfileId::AppWorker => Policy {
                provisional: false,
                runtime_key_wrap: true,
                env: &[
                    "APP_KEY",
                    "API_SECRET",
                    "DB_PASS",
                    "PROVIDER_TOKEN",
                    "WEBHOOK_HMAC",
                ],
                files: &["client.key", "client.pem"],
            },
            ProfileId::EdgeProxy => Policy {
                provisional: false,
                runtime_key_wrap: false,
                env: &["API_SECRET"],
                files: &[],
            },
            ProfileId::ApiHttp => Policy {
                provisional: true,
                runtime_key_wrap: false,
                env: &[
                    "DB_PASS",
                    "DEFUSE_KEY",
                    "MANAGEMENT_KEY",
                    "OAUTH_PRIVATE_KEY",
                    "OAUTH_PUBLIC_KEY",
                ],
                files: &["oauth-private.key", "oauth-public.key"],
            },
            ProfileId::ApiWorker => Policy {
                provisional: true,
                runtime_key_wrap: false,
                env: &["DB_PASS"],
                files: &[],
            },
        }
    }
}

impl Policy {
    pub fn allows(self, kind: Kind, name: &str) -> bool {
        match kind {
            Kind::Env => self.env.iter().any(|allowed| *allowed == name),
            Kind::File => self.files.iter().any(|allowed| *allowed == name),
        }
    }

    pub fn env_names(self) -> &'static [&'static str] {
        self.env
    }

    pub fn file_names(self) -> &'static [&'static str] {
        self.files
    }
}

pub fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

pub fn valid_env_value(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes[0] == b'#' {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_graphic() || *b == b' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_spike_profiles_separate_web_and_worker_secrets() {
        let web = ProfileId::AppWeb.policy();
        let worker = ProfileId::AppWorker.policy();
        let edge = ProfileId::EdgeProxy.policy();

        assert!(!web.allows(Kind::Env, "API_SECRET"));
        assert!(!web.allows(Kind::Env, "APP_KEY"));
        assert!(web.allows(Kind::Env, "OAUTH_CLIENT_SECRET"));

        assert!(worker.allows(Kind::Env, "API_SECRET"));
        assert!(worker.allows(Kind::Env, "APP_KEY"));
        assert!(!worker.allows(Kind::Env, "OAUTH_CLIENT_SECRET"));
        assert!(worker.runtime_key_wrap);
        assert!(!web.runtime_key_wrap);

        assert_eq!(edge.env_names(), &["API_SECRET"]);
        assert!(edge.file_names().is_empty());
        assert!(!edge.runtime_key_wrap);
    }

    #[test]
    fn only_the_worker_is_a_runtime_profile() {
        let runtime: Vec<_> = ALL
            .into_iter()
            .filter(|profile| profile.policy().runtime_key_wrap)
            .collect();
        assert_eq!(runtime, vec![ProfileId::AppWorker]);
    }

    #[test]
    fn api_profiles_are_provisional_and_share_oauth_files() {
        let http = ProfileId::ApiHttp.policy();
        let worker = ProfileId::ApiWorker.policy();
        assert!(http.provisional && worker.provisional);
        assert!(http.allows(Kind::File, "oauth-private.key"));
        assert!(http.allows(Kind::Env, "MANAGEMENT_KEY"));
        assert!(!worker.allows(Kind::Env, "MANAGEMENT_KEY"));
        assert!(worker.allows(Kind::Env, "DB_PASS"));
    }

    #[test]
    fn names_cannot_escape_the_dest_directory() {
        assert!(!valid_name("../client.key"));
        assert!(!valid_name("client/key"));
        assert!(!valid_name(""));
        assert!(valid_name("client.key"));
        assert!(valid_name("API_SECRET"));
    }

    #[test]
    fn kind_tags_round_trip_and_unknown_profile_errors() {
        assert_eq!(Kind::Env.as_str(), "env");
        assert_eq!(Kind::File.as_str(), "file");
        assert_eq!(Kind::from_tag(1), Some(Kind::Env));
        assert_eq!(Kind::from_tag(2), Some(Kind::File));
        assert_eq!(Kind::from_tag(99), None);
        assert!(ProfileId::parse("not-a-profile").is_err());
    }

    #[test]
    fn env_values_must_be_printable_single_line() {
        assert!(!valid_env_value(b""));
        assert!(!valid_env_value(b"has\nline"));
        assert!(!valid_env_value(b"#comment"));
        assert!(valid_env_value(b"ok-value"));
    }
}
