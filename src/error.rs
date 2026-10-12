use std::io;
use std::path::PathBuf;

/// Failures an operator can act on. Messages never include secret bytes.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown profile `{0}`")]
    UnknownProfile(String),
    #[error("entry `{name}` ({kind}) is not allowed in profile {profile}")]
    EntryNotAllowed {
        name: String,
        kind: &'static str,
        profile: String,
    },
    #[error("invalid entry name `{0}`")]
    InvalidName(String),
    #[error("env value for `{0}` must be a single non-empty line without '#'")]
    InvalidEnvValue(String),
    #[error("duplicate entry `{0}`")]
    DuplicateEntry(String),
    #[error("bundle is empty")]
    EmptyBundle,
    #[error("bundle profile is {found}, caller asked for {expected}")]
    ProfileMismatch { found: String, expected: String },
    #[error("bundle authentication failed")]
    BundleAuth,
    #[error("kek unwrap failed")]
    Kek,
    #[error("identity file has no AGE-SECRET-KEY line")]
    Identity,
    #[error("os random failed")]
    Random,
    #[error("destination {0} is not an empty directory")]
    DestNotEmpty(PathBuf),
    #[error("runtime body rejected")]
    RuntimeBody,
    #[error("peer uid {actual} is not allowed")]
    PeerUid { actual: u32 },
    #[error("no runtime profile bundles in {0}")]
    NoRuntimeBundles(PathBuf),
    #[error("catalog parse failed: {0}")]
    CatalogParse(String),
    #[error("profile `{0}` is not in the catalog")]
    NotInCatalog(String),
    #[error("ssm parameter `{0}` is missing")]
    SsmMissing(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}
