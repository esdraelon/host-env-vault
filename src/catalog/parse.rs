use std::collections::HashMap;

use serde::Deserialize;

use crate::core::error::Error;
use crate::legacy::profile::{valid_name, Kind};

/// Full catalog document from the SSM `SecureString` parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    profiles: HashMap<String, ProfileDefinition>,
}

/// One profile row from the catalog allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileDefinition {
    pub name: String,
    inject_env: Vec<String>,
    runtime_env: Vec<String>,
    inject_files: Vec<String>,
    runtime_files: Vec<String>,
    pub socket: bool,
    pub require_uid: Option<u32>,
    pub gid: Option<u32>,
    pub github_active_user: Option<String>,
    pub documents: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CatalogDocument {
    profiles: Vec<ProfileDefinitionRaw>,
}

#[derive(Debug, Deserialize)]
struct ProfileDefinitionRaw {
    name: String,
    #[serde(default)]
    inject: Vec<String>,
    #[serde(default)]
    runtime: Vec<String>,
    #[serde(default)]
    inject_files: Vec<String>,
    #[serde(default)]
    runtime_files: Vec<String>,
    #[serde(default)]
    socket: bool,
    require_uid: Option<u32>,
    gid: Option<u32>,
    github_active_user: Option<String>,
    #[serde(default)]
    documents: Vec<String>,
}

impl Catalog {
    pub fn from_profiles(profiles: Vec<ProfileDefinition>) -> Result<Self, Error> {
        let mut map = HashMap::new();
        for profile in profiles {
            if !valid_name(&profile.name) {
                tracing::info!(
                    target: "host_env_vault::catalog",
                    profile = %profile.name,
                    "catalog reject invalid profile name"
                );
                return Err(Error::CatalogParse(format!(
                    "invalid profile name `{}`",
                    profile.name
                )));
            }
            let name = profile.name.clone();
            if map.insert(name.clone(), profile).is_some() {
                tracing::info!(
                    target: "host_env_vault::catalog",
                    profile = %name,
                    "catalog reject duplicate profile"
                );
                return Err(Error::CatalogParse(format!("duplicate profile `{name}`")));
            }
        }
        Ok(Self { profiles: map })
    }

    pub fn profile(&self, name: &str) -> Option<&ProfileDefinition> {
        self.profiles.get(name)
    }

    pub fn profile_names(&self) -> impl Iterator<Item = &str> {
        self.profiles.keys().map(String::as_str)
    }
}

impl ProfileDefinition {
    pub fn new(
        name: impl Into<String>,
        inject_env: Vec<String>,
        runtime_env: Vec<String>,
        inject_files: Vec<String>,
        runtime_files: Vec<String>,
        socket: bool,
        require_uid: Option<u32>,
        gid: Option<u32>,
        github_active_user: Option<String>,
        documents: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            inject_env,
            runtime_env,
            inject_files,
            runtime_files,
            socket,
            require_uid,
            gid,
            github_active_user,
            documents,
        }
    }

    pub fn inject_env(&self) -> &[String] {
        &self.inject_env
    }

    pub fn runtime_env(&self) -> &[String] {
        &self.runtime_env
    }

    pub fn inject_files(&self) -> &[String] {
        &self.inject_files
    }

    pub fn runtime_files(&self) -> &[String] {
        &self.runtime_files
    }

    pub fn document_keys(&self) -> &[String] {
        &self.documents
    }

    pub fn allows_document_slot(&self, slot_name: &str) -> bool {
        self.documents
            .iter()
            .any(|key| document_basename(key).is_some_and(|base| base == slot_name))
    }

    pub fn allows_seal(&self, kind: Kind, name: &str) -> bool {
        match kind {
            Kind::Env => {
                name_in_list(&self.inject_env, name) || name_in_list(&self.runtime_env, name)
            }
            Kind::File => {
                name_in_list(&self.inject_files, name)
                    || name_in_list(&self.runtime_files, name)
                    || self.allows_document_slot(name)
            }
        }
    }

    pub fn allows_serve(&self, kind: Kind, name: &str) -> bool {
        match kind {
            Kind::Env => name_in_list(&self.runtime_env, name),
            Kind::File => name_in_list(&self.runtime_files, name),
        }
    }

    /// Entries written by `render` (injected at container start, not runtime socket).
    pub fn allows_inject(&self, kind: Kind, name: &str) -> bool {
        match kind {
            Kind::Env => name_in_list(&self.inject_env, name),
            Kind::File => name_in_list(&self.inject_files, name),
        }
    }

    fn from_raw(raw: ProfileDefinitionRaw) -> Result<Self, Error> {
        validate_name_list(&raw.inject, "inject")?;
        validate_name_list(&raw.runtime, "runtime")?;
        validate_name_list(&raw.inject_files, "inject_files")?;
        validate_name_list(&raw.runtime_files, "runtime_files")?;
        validate_document_key_list(&raw.documents)?;
        if raw.socket && raw.require_uid.is_none() {
            tracing::info!(
                target: "host_env_vault::catalog",
                profile = %raw.name,
                "catalog reject socket without require_uid"
            );
            return Err(Error::CatalogParse(format!(
                "profile `{}` has socket=true but no require_uid",
                raw.name
            )));
        }
        Ok(Self {
            name: raw.name,
            inject_env: raw.inject,
            runtime_env: raw.runtime,
            inject_files: raw.inject_files,
            runtime_files: raw.runtime_files,
            socket: raw.socket,
            require_uid: raw.require_uid,
            gid: raw.gid,
            github_active_user: raw.github_active_user,
            documents: raw.documents,
        })
    }
}

fn name_in_list(list: &[String], name: &str) -> bool {
    list.iter().any(|entry| entry == name)
}

fn document_basename(object_key: &str) -> Option<&str> {
    object_key
        .rsplit('/')
        .next()
        .filter(|part| !part.is_empty())
}

/// S3 object keys listed in the catalog (may include `/`, e.g. `nginx/site.conf`).
pub fn valid_s3_document_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 128 {
        return false;
    }
    if key.starts_with('/') || key.contains("..") {
        return false;
    }
    key.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_'))
}

fn validate_document_key_list(keys: &[String]) -> Result<(), Error> {
    for key in keys {
        if !valid_s3_document_key(key) {
            tracing::info!(
                target: "host_env_vault::catalog",
                key = %key,
                "catalog reject invalid document key"
            );
            return Err(Error::CatalogParse(format!(
                "invalid documents key `{key}`"
            )));
        }
    }
    Ok(())
}

fn validate_name_list(names: &[String], field: &str) -> Result<(), Error> {
    for name in names {
        if !valid_name(name) {
            tracing::info!(
                target: "host_env_vault::catalog",
                field,
                name = %name,
                "catalog reject invalid entry name"
            );
            return Err(Error::CatalogParse(format!(
                "invalid {field} entry name `{name}`"
            )));
        }
    }
    Ok(())
}

/// Parse catalog JSON or TOML. Whitespace-only input is rejected.
pub fn parse_catalog_text(text: &str) -> Result<Catalog, Error> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        tracing::info!(
            target: "host_env_vault::catalog",
            "catalog parse failed empty document"
        );
        return Err(Error::CatalogParse("empty catalog document".into()));
    }
    let doc: CatalogDocument = if trimmed.starts_with('{') {
        serde_json::from_str(trimmed).map_err(log_parse_failure)?
    } else {
        toml::from_str(trimmed).map_err(log_parse_failure)?
    };
    let profiles: Result<Vec<_>, _> = doc
        .profiles
        .into_iter()
        .map(ProfileDefinition::from_raw)
        .collect();
    Catalog::from_profiles(profiles?)
}

fn log_parse_failure(err: impl std::fmt::Display) -> Error {
    tracing::info!(
        target: "host_env_vault::catalog",
        error = %err,
        "catalog parse failed"
    );
    Error::CatalogParse(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_catalog_parses_worker_runtime_socket() {
        let text = r#"{
          "profiles": [{
            "name": "app-worker",
            "inject": ["DB_PASS", "STRIPE_WEBHOOK_SECRET"],
            "runtime": ["APP_KEY", "STRIPE_SECRET_KEY"],
            "inject_files": [],
            "runtime_files": ["teller.key", "teller.pem"],
            "socket": true,
            "require_uid": 33,
            "gid": 1000,
            "documents": []
          }]
        }"#;
        let catalog = parse_catalog_text(text).unwrap();
        let worker = catalog.profile("app-worker").unwrap();
        assert!(worker.socket);
        assert_eq!(worker.require_uid, Some(33));
        assert!(worker.allows_seal(Kind::Env, "DB_PASS"));
        assert!(worker.allows_serve(Kind::Env, "APP_KEY"));
        assert!(!worker.allows_serve(Kind::Env, "DB_PASS"));
        assert!(worker.allows_inject(Kind::Env, "DB_PASS"));
        assert!(!worker.allows_inject(Kind::Env, "APP_KEY"));
        assert!(!worker.allows_inject(Kind::File, "teller.key"));
        assert!(!worker.allows_inject(Kind::File, "teller.pem"));
    }

    #[test]
    fn toml_catalog_parses_github_active_user() {
        let text = r#"
[[profiles]]
name = "github"
inject = []
runtime = ["gh-user-alpha", "gh-user-beta"]
socket = false
github_active_user = "gh-user-alpha"
"#;
        let catalog = parse_catalog_text(text).unwrap();
        let gh = catalog.profile("github").unwrap();
        assert_eq!(gh.github_active_user.as_deref(), Some("gh-user-alpha"));
        assert!(gh.allows_seal(Kind::Env, "gh-user-alpha"));
    }
}
