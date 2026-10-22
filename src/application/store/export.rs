//! **Export strategy** — emit SSM migration artifacts from encrypted host store files.

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::application::sync::ssm_entry_parameter;
use crate::core::error::Error;
use crate::vault::kek::AgeKek;

use super::{store_get, store_list, StoreOptions};

/// Target format for `store export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreExportFormat {
    Ssm,
}

/// How to render a non–dry-run SSM export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreExportOutput {
    /// Bash script of `aws ssm put-parameter` calls.
    Script,
    /// JSON manifest: parameter paths and SHA256 value references (no plaintext).
    JsonManifest,
}

/// Options for exporting host store entries into SSM-shaped artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreExportSsmOptions {
    pub secrets_prefix: String,
    pub dry_run: bool,
    pub output: StoreExportOutput,
    pub profile_filter: Option<String>,
}

/// One exported parameter row (used in tests and JSON manifest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreExportParameter {
    pub name: String,
    pub profile: String,
    pub entry: String,
    pub sha256: String,
}

/// Collect decrypted entries and build export rows.
pub fn store_export_ssm(
    options: &StoreOptions,
    export: &StoreExportSsmOptions,
    kek: &AgeKek,
) -> Result<String, Error> {
    let mut listings = store_list(options, kek)?;
    if let Some(filter) = export.profile_filter.as_deref() {
        listings.retain(|row| row.profile == filter);
    }
    listings.sort_by(|a, b| a.profile.cmp(&b.profile));

    let mut rows = Vec::new();
    for listing in listings {
        for entry in &listing.entries {
            let value = store_get(options, &listing.profile, entry, kek, true)?;
            let sha256 = sha256_hex(value.as_bytes());
            let name = ssm_entry_parameter(&export.secrets_prefix, &listing.profile, entry);
            rows.push(StoreExportParameter {
                name,
                profile: listing.profile.clone(),
                entry: entry.clone(),
                sha256,
            });
        }
    }

    let body = if export.dry_run {
        info!(
            target: "host_env_vault::store",
            count = rows.len(),
            "store export: ssm dry-run"
        );
        render_dry_run(&rows)
    } else {
        match export.output {
            StoreExportOutput::Script => {
                info!(
                    target: "host_env_vault::store",
                    count = rows.len(),
                    "store export: ssm script emitted"
                );
                render_put_parameter_script(options, kek, &rows)?
            }
            StoreExportOutput::JsonManifest => {
                info!(
                    target: "host_env_vault::store",
                    count = rows.len(),
                    "store export: ssm json manifest emitted"
                );
                render_json_manifest(&export.secrets_prefix, &rows)?
            }
        }
    };

    Ok(body)
}

fn render_dry_run(rows: &[StoreExportParameter]) -> String {
    let mut out = String::new();
    for row in rows {
        let _ = writeln!(out, "{} sha256={}", row.name, row.sha256);
    }
    out
}

fn render_json_manifest(prefix: &str, rows: &[StoreExportParameter]) -> Result<String, Error> {
    #[derive(Serialize)]
    struct Manifest<'a> {
        secrets_prefix: &'a str,
        parameters: &'a [StoreExportParameter],
    }
    let manifest = Manifest {
        secrets_prefix: prefix,
        parameters: rows,
    };
    serde_json::to_string_pretty(&manifest)
        .map_err(|err| Error::CatalogParse(format!("export json: {err}")))
}

fn render_put_parameter_script(
    options: &StoreOptions,
    kek: &AgeKek,
    rows: &[StoreExportParameter],
) -> Result<String, Error> {
    let mut out = String::from("#!/usr/bin/env bash\nset -euo pipefail\n\n");
    for row in rows {
        let value = store_get(options, &row.profile, &row.entry, kek, true)?;
        let _ = writeln!(
            out,
            "aws ssm put-parameter --name {} --type SecureString --overwrite --value {}",
            shell_single_quote(&row.name),
            shell_single_quote(&value)
        );
    }
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
