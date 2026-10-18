mod adapters;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use host_env_vault::config::{
    load_config, resolve_config_path, RenderCliOverrides, ServeCliOverrides, SyncCliOverrides,
    SyncSourceKind, ValidateCliOverrides,
};
use host_env_vault::ports::{S3Error, S3Port, SsmError};
use host_env_vault::{AgeKek, ProfileId, SlotTable};

use adapters::aws_s3::AwsS3;
use adapters::aws_ssm::AwsSsm;
use adapters::process_gh::ProcessGh;

#[derive(Parser)]
#[command(
    name = "host-env-vault",
    about = "Host profile vault: sync, render, and serve secrets per profile"
)]
struct Cli {
    /// Config file path (overrides `HOST_ENV_VAULT_CONFIG` and the default path).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a new age KEK. Prints the recipient. The secret stays in the file.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Seal a staging directory into a profile bundle (legacy enum profile).
    Seal {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        r#in: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Decrypt one profile from local bundles into an empty destination.
    Render {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        dest: PathBuf,
        #[arg(long)]
        gid: Option<u32>,
    },
    /// Read-only dry-run: load catalog and secret entries without sealing bundles.
    Validate {
        #[arg(long, value_enum)]
        source: Option<SyncSource>,
        #[arg(long)]
        catalog_param: Option<String>,
        #[arg(long)]
        secrets_prefix: Option<String>,
        #[arg(long)]
        local_secrets_dir: Option<PathBuf>,
        #[arg(long)]
        s3_bucket: Option<String>,
        #[arg(long)]
        s3_prefix: Option<String>,
        /// Validate only this catalog profile (default: all profiles).
        #[arg(long)]
        profile: Option<String>,
        /// Optional per-app manifest for entry-name cross-check (see docs/validate.md).
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
    /// Pull catalog and secrets into local sealed bundles (SSM or local dev files).
    Sync {
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long, value_enum)]
        source: Option<SyncSource>,
        #[arg(long)]
        catalog_param: Option<String>,
        #[arg(long)]
        secrets_prefix: Option<String>,
        #[arg(long)]
        local_secrets_dir: Option<PathBuf>,
        #[arg(long)]
        s3_bucket: Option<String>,
        #[arg(long)]
        s3_prefix: Option<String>,
    },
    /// Load one profile's S3 document keys into the sync slot (install hook).
    FetchDocuments {
        #[arg(long)]
        profile: String,
        #[arg(long, default_value = host_env_vault::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
        #[arg(long)]
        s3_bucket: String,
        #[arg(long)]
        s3_prefix: String,
    },
    /// Serve runtime entries for one catalog profile with a unix socket.
    Serve {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
    },
    /// Load local vault material into external tools.
    Hydrate {
        #[command(subcommand)]
        target: HydrateTarget,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SyncSource {
    /// AWS Systems Manager Parameter Store (default).
    Ssm,
    /// Local directory with `catalog.json` and `{profile}.env` files.
    Local,
}

impl From<SyncSource> for SyncSourceKind {
    fn from(value: SyncSource) -> Self {
        match value {
            SyncSource::Ssm => SyncSourceKind::Ssm,
            SyncSource::Local => SyncSourceKind::Local,
        }
    }
}

#[derive(Subcommand)]
enum HydrateTarget {
    /// Feed GitHub tokens from the `github` profile bundle into `gh auth`.
    Gh {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long, default_value = host_env_vault::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("host-env-vault: {err}");
            ExitCode::from(1)
        }
    }
}

fn map_cli_s3(err: S3Error) -> host_env_vault::Error {
    match err {
        S3Error::NotFound(key) => {
            host_env_vault::Error::CatalogParse(format!("s3 object missing: {key}"))
        }
        S3Error::Unavailable => host_env_vault::Error::CatalogParse("s3 unavailable".into()),
    }
}

fn map_cli_ssm(err: SsmError) -> host_env_vault::Error {
    match err {
        SsmError::NotFound(name) => host_env_vault::Error::SsmMissing(name),
        SsmError::Unavailable => host_env_vault::Error::CatalogParse("ssm unavailable".into()),
    }
}

fn run() -> Result<(), host_env_vault::Error> {
    let cli = Cli::parse();
    let config_path = resolve_config_path(cli.config.clone());
    let file_config = load_config(&config_path)?;

    match cli.command {
        Command::Keygen { out } => {
            let kek = AgeKek::generate();
            kek.write_identity(&out)?;
            println!("{}", kek.recipient_line());
            eprintln!("wrote {}", out.display());
        }
        Command::Seal {
            profile,
            identity,
            r#in,
            out,
        } => {
            let profile = ProfileId::parse(&profile)?;
            let kek = AgeKek::read_identity(&identity)?;
            let entries = host_env_vault::read_staging(&r#in)?;
            let bundle = host_env_vault::seal(profile, entries, &kek)?;
            std::fs::write(&out, bundle)?;
            eprintln!(
                "sealed {} ({} bytes) -> {}",
                profile.as_str(),
                std::fs::metadata(&out)?.len(),
                out.display()
            );
        }
        Command::Validate {
            source,
            catalog_param,
            secrets_prefix,
            local_secrets_dir,
            s3_bucket,
            s3_prefix,
            profile,
            manifest,
        } => {
            let resolved = file_config.resolve_validate(&ValidateCliOverrides {
                source: source.map(SyncSourceKind::from),
                catalog_param,
                secrets_prefix,
                local_secrets_dir,
                s3_bucket,
                s3_prefix,
                profile,
                manifest,
            })?;
            let mut options = host_env_vault::ValidateOptions::new(
                resolved.catalog_param,
                resolved.secrets_prefix,
            );
            if let Some(filter) = resolved.profile {
                options = options.with_profile(filter);
            }
            if let Some(path) = resolved.manifest {
                options = options.with_manifest(path);
            }
            let aws_s3 = if let Some(bucket) = resolved.s3_bucket {
                options = options.with_s3_prefix(resolved.s3_prefix.unwrap_or_default());
                Some(AwsS3::from_env(bucket).map_err(map_cli_s3)?)
            } else {
                None
            };
            let s3_port = aws_s3.as_ref().map(|client| client as &dyn S3Port);
            match resolved.source {
                SyncSourceKind::Ssm => {
                    let ssm = AwsSsm::from_env().map_err(map_cli_ssm)?;
                    host_env_vault::validate_from_ssm(&ssm, &options)?;
                }
                SyncSourceKind::Local => {
                    let local_dir = resolved.local_secrets_dir.ok_or_else(|| {
                        host_env_vault::Error::CatalogParse(
                            "validate --source local requires local_secrets_dir in config or --local-secrets-dir".into(),
                        )
                    })?;
                    host_env_vault::validate_from_local(&local_dir, s3_port, &options)?;
                }
            }
        }
        Command::Sync {
            identity,
            state_dir,
            source,
            catalog_param,
            secrets_prefix,
            local_secrets_dir,
            s3_bucket,
            s3_prefix,
        } => {
            let resolved = file_config.resolve_sync(&SyncCliOverrides {
                identity,
                state_dir,
                source: source.map(SyncSourceKind::from),
                catalog_param,
                secrets_prefix,
                local_secrets_dir,
                s3_bucket,
                s3_prefix,
            })?;
            let kek = host_env_vault::load_or_create_identity(&resolved.identity)?;
            let mut table = SlotTable::new();
            let mut options = host_env_vault::SyncOptions::new(
                resolved.identity.clone(),
                resolved.state_dir.clone(),
                resolved.catalog_param,
                resolved.secrets_prefix,
            );
            let aws_s3 = if let Some(bucket) = resolved.s3_bucket {
                options = options.with_s3_prefix(resolved.s3_prefix.unwrap_or_default());
                Some(AwsS3::from_env(bucket).map_err(map_cli_s3)?)
            } else {
                None
            };
            let s3_port = aws_s3.as_ref().map(|client| client as &dyn S3Port);
            match resolved.source {
                SyncSourceKind::Ssm => {
                    let ssm = AwsSsm::from_env().map_err(map_cli_ssm)?;
                    host_env_vault::sync_from_ports(&ssm, s3_port, &kek, &mut table, &options)?;
                }
                SyncSourceKind::Local => {
                    let local_dir = resolved.local_secrets_dir.ok_or_else(|| {
                        host_env_vault::Error::CatalogParse(
                            "sync --source local requires local_secrets_dir in config or --local-secrets-dir".into(),
                        )
                    })?;
                    host_env_vault::sync_from_local(
                        &local_dir,
                        s3_port,
                        &kek,
                        &mut table,
                        &options,
                    )?;
                }
            }
            eprintln!("synced bundles into {}", resolved.state_dir.display());
        }
        Command::FetchDocuments {
            profile,
            state_dir,
            s3_bucket,
            s3_prefix,
        } => {
            let mut table = SlotTable::new();
            let options = host_env_vault::FetchDocumentsOptions::new(
                state_dir.clone(),
                s3_prefix,
                profile.clone(),
            );
            let s3 = AwsS3::from_env(s3_bucket).map_err(map_cli_s3)?;
            host_env_vault::fetch_profile_documents(&s3, &mut table, &options)?;
            eprintln!("fetched S3 documents for {profile}");
        }
        Command::Render {
            profile,
            identity,
            state_dir,
            dest,
            gid,
        } => {
            let (identity, state_dir) =
                file_config.resolve_render(&RenderCliOverrides { identity, state_dir })?;
            let kek = AgeKek::read_identity(&identity)?;
            let mut table = SlotTable::new();
            let options =
                host_env_vault::RenderOptions::new(identity, state_dir, dest.clone(), gid);
            host_env_vault::render_from_vault(&kek, &mut table, &profile, &options)?;
            eprintln!("rendered {profile} -> {}", dest.display());
        }
        Command::Serve {
            profile,
            identity,
            state_dir,
            runtime_dir,
        } => {
            let (identity, state_dir, runtime_dir) = file_config.resolve_serve(&ServeCliOverrides {
                identity,
                state_dir,
                runtime_dir,
            })?;
            let kek = AgeKek::read_identity(&identity)?;
            let mut table = SlotTable::new();
            let options = host_env_vault::ServeOptions::new(
                identity,
                state_dir,
                runtime_dir.clone(),
                profile.clone(),
            );
            let (listener, catalog) = host_env_vault::bind_serve_socket(&options)?;
            eprintln!(
                "listening on {}/sockets/{}.sock",
                runtime_dir.display(),
                profile
            );
            host_env_vault::serve_profile_forever(listener, &kek, &mut table, catalog, &options)?;
        }
        Command::Hydrate { target } => match target {
            HydrateTarget::Gh {
                identity,
                state_dir,
            } => {
                let kek = AgeKek::read_identity(&identity)?;
                let mut table = SlotTable::new();
                let options = host_env_vault::HydrateGhOptions::new(identity, state_dir.clone());
                host_env_vault::hydrate_gh_from_vault(&ProcessGh, &kek, &mut table, &options)?;
                eprintln!("hydrated gh from {}", state_dir.display());
            }
        },
    }
    Ok(())
}
