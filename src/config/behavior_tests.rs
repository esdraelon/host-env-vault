use std::path::PathBuf;

use serial_test::serial;

use super::{
    load_config, parse_config_text, parse_sync_source, resolve_config_path, FileConfig,
    RenderCliOverrides, ServeCliOverrides, SyncCliOverrides, SyncSourceKind, CONFIG_ENV_VAR,
    DEFAULT_CONFIG_PATH, DEFAULT_RUNTIME_DIR,
};
use crate::application::sync::DEFAULT_STATE_DIR;
use crate::catalog::{DEFAULT_CATALOG_PARAMETER, DEFAULT_SECRETS_PREFIX};

#[test]
fn load_config_missing_file_is_empty() {
    let path = std::env::temp_dir().join(format!(
        "host-env-vault-no-config-{}",
        std::process::id()
    ));
    let cfg = load_config(&path).unwrap();
    assert_eq!(cfg, FileConfig::default());
}

#[test]
fn load_config_reads_existing_file() {
    let dir = std::env::temp_dir().join(format!("host-env-vault-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        r#"identity = "/from/file.age"
state_dir = "/from/state"
"#,
    )
    .unwrap();
    let cfg = load_config(&path).unwrap();
    assert_eq!(cfg.identity, Some(PathBuf::from("/from/file.age")));
    assert_eq!(cfg.state_dir, Some(PathBuf::from("/from/state")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_config_invalid_toml_errors() {
    let dir = std::env::temp_dir().join(format!("host-env-vault-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.toml");
    std::fs::write(&path, "identity = [").unwrap();
    assert!(load_config(&path).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_config_non_file_path_errors() {
    let dir = std::env::temp_dir().join(format!("host-env-vault-dir-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    assert!(load_config(&dir).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_example_config() {
    let text = r#"
identity = "/etc/host-env-vault/kek.age"
state_dir = "/var/lib/host-env-vault"
runtime_dir = "/run/host-env-vault"

[sync]
source = "local"
catalog_param = "/custom/profiles"
secrets_prefix = "/custom/secrets"
local_secrets_dir = "/etc/host-env-vault/dev"
s3_bucket = "my-bucket"
s3_prefix = "recovery/"
"#;
    let cfg = parse_config_text(text).unwrap();
    assert_eq!(
        cfg,
        FileConfig {
            identity: Some(PathBuf::from("/etc/host-env-vault/kek.age")),
            state_dir: Some(PathBuf::from("/var/lib/host-env-vault")),
            runtime_dir: Some(PathBuf::from("/run/host-env-vault")),
            sync: super::SyncFileSection {
                source: Some("local".into()),
                catalog_param: Some("/custom/profiles".into()),
                secrets_prefix: Some("/custom/secrets".into()),
                local_secrets_dir: Some(PathBuf::from("/etc/host-env-vault/dev")),
                store_dir: None,
                manifests_dir: None,
                s3_bucket: Some("my-bucket".into()),
                s3_prefix: Some("recovery/".into()),
            },
        }
    );
}

#[test]
#[serial]
fn resolve_config_path_cli_over_env() {
    let _guard = env_lock(CONFIG_ENV_VAR, "/env/config.toml");
    let path = resolve_config_path(Some(PathBuf::from("/cli/config.toml")));
    assert_eq!(path, PathBuf::from("/cli/config.toml"));
}

#[test]
#[serial]
fn resolve_config_path_env_over_default() {
    let _guard = env_lock(CONFIG_ENV_VAR, "/env/config.toml");
    let path = resolve_config_path(None);
    assert_eq!(path, PathBuf::from("/env/config.toml"));
}

#[test]
#[serial]
fn resolve_config_path_default_when_unset() {
    let _guard = env_lock(CONFIG_ENV_VAR, "");
    let path = resolve_config_path(None);
    assert_eq!(path, PathBuf::from(DEFAULT_CONFIG_PATH));
}

#[test]
fn sync_merge_defaults_only() {
    let cfg = FileConfig::default();
    let resolved = cfg.resolve_sync(&SyncCliOverrides {
        identity: Some(PathBuf::from("/id.age")),
        ..Default::default()
    }).unwrap();
    assert_eq!(resolved.identity, PathBuf::from("/id.age"));
    assert_eq!(resolved.state_dir, PathBuf::from(DEFAULT_STATE_DIR));
    assert_eq!(resolved.source, SyncSourceKind::Ssm);
    assert_eq!(resolved.catalog_param, DEFAULT_CATALOG_PARAMETER);
    assert_eq!(resolved.secrets_prefix, DEFAULT_SECRETS_PREFIX);
    assert!(resolved.local_secrets_dir.is_none());
}

#[test]
fn sync_merge_file_over_defaults() {
    let cfg = parse_config_text(
        r#"
identity = "/file/id.age"
state_dir = "/file/state"
[sync]
source = "local"
catalog_param = "/file/catalog"
secrets_prefix = "/file/prefix"
local_secrets_dir = "/file/dev"
"#,
    )
    .unwrap();
    let resolved = cfg.resolve_sync(&SyncCliOverrides::default()).unwrap();
    assert_eq!(resolved.identity, PathBuf::from("/file/id.age"));
    assert_eq!(resolved.state_dir, PathBuf::from("/file/state"));
    assert_eq!(resolved.source, SyncSourceKind::Local);
    assert_eq!(resolved.catalog_param, "/file/catalog");
    assert_eq!(resolved.secrets_prefix, "/file/prefix");
    assert_eq!(
        resolved.local_secrets_dir,
        Some(PathBuf::from("/file/dev"))
    );
}

#[test]
fn sync_merge_cli_over_file() {
    let cfg = parse_config_text(
        r#"
identity = "/file/id.age"
state_dir = "/file/state"
[sync]
source = "ssm"
catalog_param = "/file/catalog"
secrets_prefix = "/file/prefix"
"#,
    )
    .unwrap();
    let resolved = cfg
        .resolve_sync(&SyncCliOverrides {
            identity: Some(PathBuf::from("/cli/id.age")),
            state_dir: Some(PathBuf::from("/cli/state")),
            source: Some(SyncSourceKind::Local),
            catalog_param: Some("/cli/catalog".into()),
            secrets_prefix: Some("/cli/prefix".into()),
            local_secrets_dir: Some(PathBuf::from("/cli/dev")),
            s3_bucket: Some("b".into()),
            s3_prefix: Some("p/".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(resolved.identity, PathBuf::from("/cli/id.age"));
    assert_eq!(resolved.state_dir, PathBuf::from("/cli/state"));
    assert_eq!(resolved.source, SyncSourceKind::Local);
    assert_eq!(resolved.catalog_param, "/cli/catalog");
    assert_eq!(resolved.secrets_prefix, "/cli/prefix");
    assert_eq!(
        resolved.local_secrets_dir,
        Some(PathBuf::from("/cli/dev"))
    );
    assert_eq!(resolved.s3_bucket.as_deref(), Some("b"));
    assert_eq!(resolved.s3_prefix.as_deref(), Some("p/"));
}

#[test]
fn sync_merge_partial_cli_keeps_file_for_rest() {
    let cfg = parse_config_text(
        r#"
identity = "/file/id.age"
[sync]
catalog_param = "/file/catalog"
"#,
    )
    .unwrap();
    let resolved = cfg
        .resolve_sync(&SyncCliOverrides {
            state_dir: Some(PathBuf::from("/cli/state")),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(resolved.identity, PathBuf::from("/file/id.age"));
    assert_eq!(resolved.state_dir, PathBuf::from("/cli/state"));
    assert_eq!(resolved.catalog_param, "/file/catalog");
    assert_eq!(resolved.secrets_prefix, DEFAULT_SECRETS_PREFIX);
}

#[test]
fn render_and_serve_read_shared_paths_from_file() {
    let cfg = parse_config_text(
        r#"
identity = "/file/id.age"
state_dir = "/file/state"
runtime_dir = "/file/run"
"#,
    )
    .unwrap();
    let (id, state) = cfg.resolve_render(&RenderCliOverrides::default()).unwrap();
    assert_eq!(id, PathBuf::from("/file/id.age"));
    assert_eq!(state, PathBuf::from("/file/state"));

    let (id, state, runtime) = cfg.resolve_serve(&ServeCliOverrides::default()).unwrap();
    assert_eq!(id, PathBuf::from("/file/id.age"));
    assert_eq!(state, PathBuf::from("/file/state"));
    assert_eq!(runtime, PathBuf::from("/file/run"));
}

#[test]
fn serve_runtime_default_when_not_in_file_or_cli() {
    let cfg = FileConfig::default();
    let (_id, _state, runtime) = cfg
        .resolve_serve(&ServeCliOverrides {
            identity: Some(PathBuf::from("/id.age")),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(runtime, PathBuf::from(DEFAULT_RUNTIME_DIR));
}

#[test]
fn parse_sync_source_rejects_unknown() {
    assert!(parse_sync_source("aws").is_err());
}

#[test]
fn parse_sync_source_accepts_host_store() {
    assert_eq!(parse_sync_source("host-store").unwrap(), SyncSourceKind::HostStore);
}

#[test]
fn sync_merge_default_store_dir_under_state() {
    let cfg = FileConfig::default();
    let resolved = cfg
        .resolve_sync(&SyncCliOverrides {
            identity: Some(PathBuf::from("/id.age")),
            state_dir: Some(PathBuf::from("/var/state")),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(resolved.store_dir, PathBuf::from("/var/state/store"));
}

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        if value.is_empty() {
            // SAFETY: test-only; single-threaded mutation tests use RUST_TEST_THREADS=1 elsewhere.
            unsafe { std::env::remove_var(key) };
        } else {
            unsafe { std::env::set_var(key, value) };
        }
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(v) => unsafe { std::env::set_var(self.key, v) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

fn env_lock(key: &'static str, value: &str) -> EnvGuard {
    EnvGuard::set(key, value)
}
