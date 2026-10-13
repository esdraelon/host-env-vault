use crate::core::error::Error;

/// A security personality. The name is the only selector. Callers never pass a
/// second profile inside a bundle or a socket frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileId {
    DenariusWeb,
    DenariusWorker,
    DenariusConnect,
    IdpHttp,
    IdpWorker,
}

pub const ALL: [ProfileId; 5] = [
    ProfileId::DenariusWeb,
    ProfileId::DenariusWorker,
    ProfileId::DenariusConnect,
    ProfileId::IdpHttp,
    ProfileId::IdpWorker,
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

/// Allowlist for one profile. `provisional` means the IDP split is a hypothesis
/// until each process is traced. Seal still refuses names outside the list.
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
            ProfileId::DenariusWeb => "denarius-web",
            ProfileId::DenariusWorker => "denarius-worker",
            ProfileId::DenariusConnect => "denarius-connect",
            ProfileId::IdpHttp => "idp-http",
            ProfileId::IdpWorker => "idp-worker",
        }
    }

    pub fn parse(name: &str) -> Result<Self, Error> {
        ALL.into_iter()
            .find(|profile| profile.as_str() == name)
            .ok_or_else(|| Error::UnknownProfile(name.to_owned()))
    }

    pub fn policy(self) -> Policy {
        match self {
            ProfileId::DenariusWeb => Policy {
                provisional: false,
                runtime_key_wrap: false,
                env: &["DB_PASS", "IDP_CLIENT_SECRET", "STRIPE_PUBLISHABLE_KEY"],
                files: &[],
            },
            ProfileId::DenariusWorker => Policy {
                provisional: false,
                runtime_key_wrap: true,
                env: &[
                    "APP_KEY",
                    "DB_PASS",
                    "PLAID_SECRET",
                    "SIMPLEFIN_APP_TOKEN",
                    "STRIPE_SECRET_KEY",
                    "STRIPE_WEBHOOK_SECRET",
                    "TELLER_WEBHOOK_SECRET",
                ],
                files: &["teller.key", "teller.pem"],
            },
            ProfileId::DenariusConnect => Policy {
                provisional: false,
                runtime_key_wrap: false,
                env: &["STRIPE_SECRET_KEY"],
                files: &[],
            },
            // Hypothesis until amtgardidpapp and jwt-pvh-worker.php are traced.
            // Overlap is explicit: both may still open the signing key.
            ProfileId::IdpHttp => Policy {
                provisional: true,
                runtime_key_wrap: false,
                env: &[
                    "AMAZON_SES_PASSWORD",
                    "APP_SECRET",
                    "AUTH_SERVER_DEFUSE_KEY",
                    "DB_PASS",
                    "DISCORD_CLIENT_SECRET",
                    "FACEBOOK_CLIENT_SECRET",
                    "GOOGLE_CLIENT_SECRET",
                    "IDP_ORK_SHARED_SECRET",
                    "JWT_KEY",
                    "MAILBOX_CODE_PEPPER",
                    "MANAGEMENT_KEY",
                    "OAUTH_ENCRYPTION_KEY",
                    "SENDGRID_API_KEY",
                ],
                files: &["apple.p8", "oauth-private.key"],
            },
            ProfileId::IdpWorker => Policy {
                provisional: true,
                runtime_key_wrap: false,
                env: &["DB_PASS", "JWT_KEY"],
                files: &["oauth-private.key"],
            },
        }
    }
}

impl Policy {
    pub fn allows(self, kind: Kind, name: &str) -> bool {
        let names = match kind {
            Kind::Env => self.env,
            Kind::File => self.files,
        };
        names.contains(&name)
    }

    pub fn env_names(self) -> &'static [&'static str] {
        self.env
    }

    pub fn file_names(self) -> &'static [&'static str] {
        self.files
    }
}

pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let [first, rest @ ..] = bytes else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// Single-line env values. `#` would become a dotenv comment. Newlines would
/// break the file. File entries are raw bytes and use a different check.
pub fn valid_env_value(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii() && *byte >= b' ' && *byte != b'#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denarius_personalities_do_not_share_stripe_secret_material() {
        let web = ProfileId::DenariusWeb.policy();
        let worker = ProfileId::DenariusWorker.policy();
        let connect = ProfileId::DenariusConnect.policy();

        assert!(!web.allows(Kind::Env, "STRIPE_SECRET_KEY"));
        assert!(!web.allows(Kind::Env, "APP_KEY"));
        assert!(web.allows(Kind::Env, "STRIPE_PUBLISHABLE_KEY"));

        assert!(worker.allows(Kind::Env, "STRIPE_SECRET_KEY"));
        assert!(worker.allows(Kind::Env, "APP_KEY"));
        assert!(!worker.allows(Kind::Env, "STRIPE_PUBLISHABLE_KEY"));
        assert!(worker.runtime_key_wrap);
        assert!(!web.runtime_key_wrap);

        assert_eq!(connect.env_names(), &["STRIPE_SECRET_KEY"]);
        assert!(connect.file_names().is_empty());
        assert!(!connect.runtime_key_wrap);
    }

    #[test]
    fn only_the_worker_is_a_runtime_profile() {
        let runtime: Vec<_> = ALL
            .into_iter()
            .filter(|profile| profile.policy().runtime_key_wrap)
            .collect();
        assert_eq!(runtime, vec![ProfileId::DenariusWorker]);
    }

    #[test]
    fn idp_allowlists_are_provisional_and_overlap_on_the_signing_key() {
        let http = ProfileId::IdpHttp.policy();
        let worker = ProfileId::IdpWorker.policy();
        assert!(http.provisional && worker.provisional);
        assert!(http.allows(Kind::File, "oauth-private.key"));
        assert!(worker.allows(Kind::File, "oauth-private.key"));
        assert!(http.allows(Kind::Env, "SENDGRID_API_KEY"));
        assert!(!worker.allows(Kind::Env, "SENDGRID_API_KEY"));
    }

    #[test]
    fn names_cannot_escape_the_dest_directory() {
        assert!(!valid_name("../teller.key"));
        assert!(!valid_name("teller/key"));
        assert!(!valid_name(""));
        assert!(valid_name("teller.key"));
        assert!(valid_name("STRIPE_SECRET_KEY"));
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
