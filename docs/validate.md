# Validate (sync dry-run)

`host-env-vault validate` is a **read-only** operator check: load the catalog, run **manifest preflight** for each profile, then load every secret entry the way `sync` would—without creating a KEK, writing a catalog snapshot, or sealing `.hev` bundles.

Use it in CI or before a production sync to catch missing manifests, catalog/manifest mismatches, missing SSM parameters, oversize values, invalid env lines, and (when configured) missing S3 document keys.

## CLI

Same config resolution as `sync` (`--config`, `HOST_ENV_VAULT_CONFIG`, top-level `state_dir`, `[sync]` table, `--source ssm|local`, `catalog_param`, `secrets_prefix`, `local_secrets_dir`, optional `manifests_dir`, optional `s3_bucket` / `s3_prefix`).

```bash
host-env-vault validate
host-env-vault validate --profile app-web
host-env-vault validate --source local --local-secrets-dir ./dev-shared/secrets
```

Optional **`--manifest PATH`** with **`--profile NAME`**: load that file instead of discovery for the single profile under check (escape hatch for app-repo CI).

Exit code is non-zero when any profile fails. Stdout prints one success line per profile; stderr summarizes failures.

## Per-profile manifest (required)

Each catalog profile must have a TOML manifest named **`{profile}.env-host-vault`**. Lists under `[inject]` and `[runtime]` must **exactly match** the catalog allowlists (env and file names). Extra names on either side fail with `ManifestMismatch`.

Example `app-web.env-host-vault`:

```toml
profile = "app-web"

[inject]
env = ["DB_PASS", "SESSION_SECRET"]
files = []

[runtime]
env = []
files = []
```

### Discovery (no `--manifest` for normal ops)

Resolution order for profile `P`:

1. **`source = local`** and `{local_secrets_dir}/P.env-host-vault` exists → use that path.
2. Otherwise `{manifests_dir}/P.env-host-vault`.

Defaults:

- `manifests_dir` — `[sync] manifests_dir` in config, or `{state_dir}/manifests`.
- `state_dir` — config / `--state-dir` on validate (default `/var/lib/host-env-vault`).

A **missing manifest file is a hard failure** for both `validate` and `sync`.

## Sync preflight and stale bundles

`sync` runs the same manifest preflight **before** pulling secrets. On preflight failure (missing manifest or mismatch), sync **does not replace** `{profile}.hev`, writes `{state_dir}/{profile}.stale`, and counts the profile toward `SyncFailed`. A successful sync **removes** `{profile}.stale`.

`render` always adds a synthetic inject line (not part of the catalog):

- `ENV_HOST_VAULT_STALE=true` when `{profile}.stale` exists
- `ENV_HOST_VAULT_STALE=false` otherwise

See [compositional catalog](compositional-catalog.md) for how profile fragments merge before sync.

When leaving host-store transition mode, use [transition.md](transition.md) for `store export` and the SSM cutover checklist.
