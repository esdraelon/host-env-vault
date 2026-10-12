use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use host_env_vault::{AgeKek, ProfileId, RenderMode};

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
    /// Decrypt one profile into an empty directory of mode-0400 files.
    Render {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        dest: PathBuf,
        /// Group that may read the files. Directory stays root-owned.
        #[arg(long)]
        gid: Option<u32>,
    },
    /// Serve runtime key wrap for profiles that have a socket. No TCP listener.
    Serve {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        runtime_dir: PathBuf,
        #[arg(long)]
        require_uid: Option<u32>,
        #[arg(long, default_value_t = 3600)]
        poll_secs: u64,
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
        Command::Render {
            profile,
            identity,
            bundle,
            dest,
            gid,
        } => {
            let profile = ProfileId::parse(&profile)?;
            let kek = AgeKek::read_identity(&identity)?;
            let bytes = std::fs::read(&bundle)?;
            let opened = host_env_vault::open(&bytes, &kek)?;
            if opened.profile != profile {
                return Err(host_env_vault::Error::ProfileMismatch {
                    found: opened.profile.as_str().to_owned(),
                    expected: profile.as_str().to_owned(),
                });
            }
            host_env_vault::render(&dest, &opened.entries, RenderMode::from_gid(gid))?;
            eprintln!("rendered {} -> {}", profile.as_str(), dest.display());
        }
        Command::Serve {
            identity,
            state_dir,
            runtime_dir,
            require_uid,
            poll_secs,
        } => {
            let kek = AgeKek::read_identity(&identity)?;
            let listener = host_env_vault::serve::bind_runtime_socket(
                &runtime_dir,
                ProfileId::DenariusWorker,
            )?;
            eprintln!(
                "listening on {}/sockets/denarius-worker.sock",
                runtime_dir.display()
            );
            host_env_vault::serve::serve_forever(
                listener,
                &state_dir,
                &kek,
                require_uid,
                Duration::from_secs(poll_secs),
            )?;
        }
    }
    Ok(())
}
