use std::path::PathBuf;
use std::process::ExitCode;
use clap::{Parser, Subcommand};
use host_env_vault::port::{S3Error, S3Port, SsmError, SsmPort};
use host_env_vault::{AgeKek, ProfileId};

mod aws_s3 {
    use super::{S3Error, S3Port};
    use aws_sdk_s3::error::ProvideErrorMetadata;

    pub struct AwsS3 {
        client: aws_sdk_s3::Client,
        bucket: String,
        rt: tokio::runtime::Runtime,
    }

    impl AwsS3 {
        pub fn from_env(bucket: String) -> Result<Self, S3Error> {
            let rt = tokio::runtime::Runtime::new().map_err(|_| S3Error::Unavailable)?;
            let client = rt.block_on(async {
                let config = aws_config::load_from_env().await;
                aws_sdk_s3::Client::new(&config)
            });
            Ok(Self { client, bucket, rt })
        }
    }

    impl S3Port for AwsS3 {
        fn get_object(&self, key: &str) -> Result<Vec<u8>, S3Error> {
            self.rt.block_on(async {
                let response = self
                    .client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .send()
                    .await;
                match response {
                    Ok(output) => {
                        let bytes = output.body.collect().await.map_err(|_| S3Error::Unavailable)?;
                        Ok(bytes.into_bytes().to_vec())
                    }
                    Err(err) => {
                        if err.code() == Some("NoSuchKey") {
                            Err(S3Error::NotFound(key.to_owned()))
                        } else {
                            Err(S3Error::Unavailable)
                        }
                    }
                }
            })
        }
    }
}

mod aws_ssm {
    use super::{SsmError, SsmPort};
    use aws_sdk_ssm::error::ProvideErrorMetadata;

    pub struct AwsSsm {
        client: aws_sdk_ssm::Client,
        rt: tokio::runtime::Runtime,
    }

    impl AwsSsm {
        pub fn from_env() -> Result<Self, SsmError> {
            let rt = tokio::runtime::Runtime::new().map_err(|_| SsmError::Unavailable)?;
            let client = rt.block_on(async {
                let config = aws_config::load_from_env().await;
                aws_sdk_ssm::Client::new(&config)
            });
            Ok(Self { client, rt })
        }
    }

    impl SsmPort for AwsSsm {
        fn get_parameter(&self, name: &str) -> Result<String, SsmError> {
            self.rt.block_on(async {
                let response = self
                    .client
                    .get_parameter()
                    .name(name)
                    .with_decryption(true)
                    .send()
                    .await;
                match response {
                    Ok(output) => output
                        .parameter()
                        .and_then(|parameter| parameter.value())
                        .map(|value| value.to_owned())
                        .ok_or_else(|| SsmError::NotFound(name.to_owned())),
                    Err(err) => {
                        if err.code() == Some("ParameterNotFound") {
                            Err(SsmError::NotFound(name.to_owned()))
                        } else {
                            Err(SsmError::Unavailable)
                        }
                    }
                }
            })
        }
    }
}

#[derive(Parser)]
#[command(
    name = "host-env-vault",
    about = "Host profile vault for Denarius and the IDP"
)]
struct Cli {
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
    /// Seal a staging directory into a profile bundle.
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
        identity: PathBuf,
        #[arg(long, default_value = host_env_vault::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
        #[arg(long)]
        dest: PathBuf,
        /// Group that may read the files. Overrides the catalog gid when set.
        #[arg(long)]
        gid: Option<u32>,
    },
    /// Pull catalog and secrets from SSM into local sealed bundles.
    Sync {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long, default_value = host_env_vault::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
        #[arg(long, default_value = host_env_vault::DEFAULT_CATALOG_PARAMETER)]
        catalog_param: String,
        /// S3 bucket for catalog document keys (optional).
        #[arg(long)]
        s3_bucket: Option<String>,
        /// Key prefix inside the bucket for recovery documents.
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
        identity: PathBuf,
        #[arg(long, default_value = host_env_vault::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
        #[arg(long)]
        runtime_dir: PathBuf,
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
        S3Error::NotFound(key) => host_env_vault::Error::CatalogParse(format!("s3 object missing: {key}")),
        S3Error::Unavailable => host_env_vault::Error::CatalogParse("s3 unavailable".into()),
    }
}

fn map_cli_ssm(err: SsmError) -> host_env_vault::Error {
    match err {
        SsmError::NotFound(name) => host_env_vault::Error::SsmMissing(name),
        SsmError::Unavailable => {
            host_env_vault::Error::CatalogParse("ssm unavailable".into())
        }
    }
}

fn run() -> Result<(), host_env_vault::Error> {
    match Cli::parse().command {
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
        Command::Sync {
            identity,
            state_dir,
            catalog_param,
            s3_bucket,
            s3_prefix,
        } => {
            let kek = host_env_vault::load_or_create_identity(&identity)?;
            let mut table = host_env_vault::slot::SlotTable::new();
            let mut options =
                host_env_vault::SyncOptions::new(identity, state_dir.clone(), catalog_param);
            let ssm = aws_ssm::AwsSsm::from_env().map_err(map_cli_ssm)?;
            if let Some(bucket) = s3_bucket {
                options = options.with_s3_prefix(s3_prefix.unwrap_or_default());
                let s3 = aws_s3::AwsS3::from_env(bucket).map_err(map_cli_s3)?;
                host_env_vault::sync_from_ports(&ssm, Some(&s3), &kek, &mut table, &options)?;
            } else {
                host_env_vault::sync_from_ssm(&ssm, &kek, &mut table, &options)?;
            }
            eprintln!("synced bundles into {}", state_dir.display());
        }
        Command::FetchDocuments {
            profile,
            state_dir,
            s3_bucket,
            s3_prefix,
        } => {
            let mut table = host_env_vault::slot::SlotTable::new();
            let options = host_env_vault::FetchDocumentsOptions::new(
                state_dir.clone(),
                s3_prefix,
                profile.clone(),
            );
            let s3 = aws_s3::AwsS3::from_env(s3_bucket).map_err(map_cli_s3)?;
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
            let kek = AgeKek::read_identity(&identity)?;
            let mut table = host_env_vault::slot::SlotTable::new();
            let options = host_env_vault::RenderOptions::new(identity, state_dir, dest.clone(), gid);
            host_env_vault::render_from_vault(&kek, &mut table, &profile, &options)?;
            eprintln!("rendered {profile} -> {}", dest.display());
        }
        Command::Serve {
            profile,
            identity,
            state_dir,
            runtime_dir,
        } => {
            let kek = AgeKek::read_identity(&identity)?;
            let mut table = host_env_vault::slot::SlotTable::new();
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
    }
    Ok(())
}
