mod adapters;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use host_env_vault::config::{
    load_config, resolve_config_path, RenderCliOverrides, ServeCliOverrides, StoreCliOverrides,
    SyncCliOverrides, SyncSourceKind, ValidateCliOverrides,
};
use host_env_vault::ports::{S3Error, S3Port, SsmError};
use host_env_vault::{
    resolve_field, resolve_secret_value, store_export_ssm, store_get, store_import_from_dev_dir,
    store_import_from_env_file, store_init, store_list, store_put, store_remove, store_rekey,
    AgeKek, ProfileId, SlotTable, StoreExportOutput, StoreExportSsmOptions, StoreOptions,
};

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
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, value_enum)]
        source: Option<SyncSource>,
        #[arg(long)]
        store_dir: Option<PathBuf>,
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
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Override manifest path for a single `--profile` (default: per-profile discovery).
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
        store_dir: Option<PathBuf>,
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
    /// Manage encrypted per-profile host store files (transition mode).
    Store(StoreCli),
}

#[derive(Parser)]
struct StoreCli {
    #[arg(long)]
    identity: Option<PathBuf>,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long)]
    store_dir: Option<PathBuf>,
    /// Fail instead of prompting when required fields are missing.
    #[arg(long)]
    non_interactive: bool,
    #[command(subcommand)]
    command: StoreCommand,
}

#[derive(Subcommand)]
enum StoreCommand {
    /// Create the store directory and ensure the host age identity exists.
    Init,
    /// Upsert one secret entry for a catalog profile.
    #[command(visible_alias = "set")]
    Put {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        value: Option<String>,
        #[arg(long)]
        value_file: Option<PathBuf>,
    },
    /// Read one entry (masked unless `--show`).
    Get {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        name: Option<String>,
        /// Print the plaintext secret (default output is masked).
        #[arg(long)]
        show: bool,
    },
    /// List profiles and entry names in the store.
    List {
        /// Limit output to one profile.
        #[arg(long)]
        profile: Option<String>,
    },
    /// Delete one entry from a profile store file.
    Remove {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        name: Option<String>,
    },
    /// Import from a dev layout directory or a single profile env file.
    Import {
        /// Directory with `catalog.json`, `{profile}.env`, and optional `files/`.
        #[arg(long)]
        from_dir: Option<PathBuf>,
        /// Env file whose keys are imported into `--profile`.
        #[arg(long)]
        from_env_file: Option<PathBuf>,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Re-encrypt all profile store files with a new host age identity.
    Rekey {
        #[arg(long)]
        new_identity: PathBuf,
    },
    /// Emit SSM migration artifacts from the encrypted host store.
    Export {
        #[arg(long, value_enum)]
        format: CliStoreExportFormat,
        /// Print parameter paths and SHA256 only (no script or manifest body).
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        secrets_prefix: Option<String>,
        /// Limit export to one catalog profile.
        #[arg(long)]
        profile: Option<String>,
        /// Write JSON manifest (SHA256 references) instead of a put-parameter shell script.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliStoreExportFormat {
    Ssm,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SyncSource {
    /// AWS Systems Manager Parameter Store (default).
    Ssm,
    /// Local directory with `catalog.json` and `{profile}.env` files.
    Local,
    /// Encrypted per-profile files under `store_dir`; catalog from SSM or local `catalog.json`.
    HostStore,
}

impl From<SyncSource> for SyncSourceKind {
    fn from(value: SyncSource) -> Self {
        match value {
            SyncSource::Ssm => SyncSourceKind::Ssm,
            SyncSource::Local => SyncSourceKind::Local,
            SyncSource::HostStore => SyncSourceKind::HostStore,
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
            identity,
            source,
            catalog_param,
            secrets_prefix,
            local_secrets_dir,
            store_dir,
            s3_bucket,
            s3_prefix,
            profile,
            state_dir,
            manifest,
        } => {
            let resolved = file_config.resolve_validate(&ValidateCliOverrides {
                identity,
                state_dir,
                source: source.map(SyncSourceKind::from),
                catalog_param,
                secrets_prefix,
                local_secrets_dir,
                store_dir,
                manifests_dir: None,
                s3_bucket,
                s3_prefix,
                profile,
                manifest,
            })?;
            let mut options = host_env_vault::ValidateOptions::new(
                resolved.catalog_param,
                resolved.secrets_prefix,
            )
            .with_manifest_lookup(
                resolved.state_dir,
                resolved.source,
                resolved.local_secrets_dir.clone(),
                resolved.manifests_dir,
            );
            if let Some(filter) = resolved.profile {
                options = options.with_profile(filter);
            }
            if let Some(path) = resolved.manifest {
                options = options.with_manifest_override(path);
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
                SyncSourceKind::HostStore => {
                    let identity_path = resolved.identity.ok_or_else(|| {
                        host_env_vault::Error::CatalogParse(
                            "validate --source host-store requires identity in config or --identity".into(),
                        )
                    })?;
                    let kek = AgeKek::read_identity(&identity_path)?;
                    if let Some(local_dir) = resolved.local_secrets_dir {
                        let catalog = host_env_vault::LocalSecretSource::new(&local_dir);
                        host_env_vault::validate_from_host_store(
                            &catalog,
                            &resolved.store_dir,
                            &kek,
                            s3_port,
                            &options,
                        )?;
                    } else {
                        let ssm = AwsSsm::from_env().map_err(map_cli_ssm)?;
                        let catalog = host_env_vault::SsmSecretSource::new(
                            &options.catalog_param,
                            &options.secrets_prefix,
                            &ssm,
                        );
                        host_env_vault::validate_from_host_store(
                            &catalog,
                            &resolved.store_dir,
                            &kek,
                            s3_port,
                            &options,
                        )?;
                    }
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
            store_dir,
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
                store_dir,
                manifests_dir: None,
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
            )
            .with_manifest_lookup(
                resolved.source,
                resolved.local_secrets_dir.as_ref().cloned(),
                resolved.manifests_dir.clone(),
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
                SyncSourceKind::HostStore => {
                    if let Some(local_dir) = resolved.local_secrets_dir {
                        let catalog = host_env_vault::LocalSecretSource::new(&local_dir);
                        host_env_vault::sync_from_host_store(
                            &catalog,
                            &resolved.store_dir,
                            &kek,
                            s3_port,
                            &mut table,
                            &options,
                        )?;
                    } else {
                        let ssm = AwsSsm::from_env().map_err(map_cli_ssm)?;
                        let catalog = host_env_vault::SsmSecretSource::new(
                            &options.catalog_param,
                            &options.secrets_prefix,
                            &ssm,
                        );
                        host_env_vault::sync_from_host_store(
                            &catalog,
                            &resolved.store_dir,
                            &kek,
                            s3_port,
                            &mut table,
                            &options,
                        )?;
                    }
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
        Command::Store(store_cli) => run_store(&file_config, store_cli)?,
    }
    Ok(())
}

fn run_store(
    file_config: &host_env_vault::FileConfig,
    store_cli: StoreCli,
) -> Result<(), host_env_vault::Error> {
    let resolved = file_config.resolve_store(&StoreCliOverrides {
        identity: store_cli.identity,
        state_dir: store_cli.state_dir,
        store_dir: store_cli.store_dir,
        secrets_prefix: None,
    })?;
    let options = StoreOptions {
        identity_path: resolved.identity.clone(),
        store_dir: resolved.store_dir.clone(),
    };
    let non_interactive = store_cli.non_interactive;
    match store_cli.command {
        StoreCommand::Init => {
            store_init(&options)?;
            eprintln!(
                "store ready at {} (identity {})",
                options.store_dir.display(),
                options.identity_path.display()
            );
        }
        StoreCommand::Put {
            profile,
            name,
            value,
            value_file,
        } => {
            let profile = resolve_field("profile", profile, non_interactive)?;
            let name = resolve_field("entry name", name, non_interactive)?;
            let secret = resolve_secret_value(value, value_file, non_interactive)?;
            let kek = AgeKek::read_identity(&options.identity_path)?;
            store_put(&options, &profile, &name, &secret, &kek)?;
            eprintln!("stored {profile}/{name}");
        }
        StoreCommand::Get {
            profile,
            name,
            show,
        } => {
            let profile = resolve_field("profile", profile, non_interactive)?;
            let name = resolve_field("entry name", name, non_interactive)?;
            let kek = AgeKek::read_identity(&options.identity_path)?;
            let out = store_get(&options, &profile, &name, &kek, show)?;
            println!("{out}");
        }
        StoreCommand::List { profile } => {
            let kek = AgeKek::read_identity(&options.identity_path)?;
            let mut listings = store_list(&options, &kek)?;
            if let Some(filter) = profile {
                listings.retain(|row| row.profile == filter);
            }
            if listings.is_empty() {
                eprintln!("(no profiles in store)");
            } else {
                for row in listings {
                    println!("{}:", row.profile);
                    for entry in row.entries {
                        println!("  {entry}");
                    }
                }
            }
        }
        StoreCommand::Remove { profile, name } => {
            let profile = resolve_field("profile", profile, non_interactive)?;
            let name = resolve_field("entry name", name, non_interactive)?;
            let kek = AgeKek::read_identity(&options.identity_path)?;
            store_remove(&options, &profile, &name, &kek)?;
            eprintln!("removed {profile}/{name}");
        }
        StoreCommand::Import {
            from_dir,
            from_env_file,
            profile,
        } => {
            let kek = AgeKek::read_identity(&options.identity_path)?;
            match (from_dir, from_env_file) {
                (Some(dir), None) => {
                    let count =
                        store_import_from_dev_dir(&options, &dir, profile.as_deref(), &kek)?;
                    eprintln!("imported {count} entries from {}", dir.display());
                }
                (None, Some(path)) => {
                    let profile = resolve_field("profile", profile, non_interactive)?;
                    let count = store_import_from_env_file(&options, &profile, &path, &kek)?;
                    eprintln!("imported {count} entries from {}", path.display());
                }
                (Some(_), Some(_)) => {
                    return Err(host_env_vault::Error::CatalogParse(
                        "import: pass only one of --from-dir or --from-env-file".into(),
                    ));
                }
                (None, None) => {
                    return Err(host_env_vault::Error::CatalogParse(
                        "import: pass --from-dir or --from-env-file".into(),
                    ));
                }
            }
        }
        StoreCommand::Rekey { new_identity } => {
            let old_kek = AgeKek::read_identity(&options.identity_path)?;
            let new_kek = AgeKek::read_identity(&new_identity)?;
            let count = store_rekey(&options, &old_kek, &new_kek)?;
            eprintln!(
                "rekeyed {count} profile store files (new identity {})",
                new_identity.display()
            );
        }
        StoreCommand::Export {
            format: _,
            dry_run,
            secrets_prefix,
            profile,
            json,
        } => {
            let prefix = secrets_prefix.unwrap_or(resolved.secrets_prefix);
            let kek = AgeKek::read_identity(&options.identity_path)?;
            let output = if json {
                StoreExportOutput::JsonManifest
            } else {
                StoreExportOutput::Script
            };
            let body = store_export_ssm(
                &options,
                &StoreExportSsmOptions {
                    secrets_prefix: prefix,
                    dry_run,
                    output,
                    profile_filter: profile,
                },
                &kek,
            )?;
            print!("{body}");
        }
    }
    Ok(())
}
