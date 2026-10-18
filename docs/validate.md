# Validate (sync dry-run)

`host-env-vault validate` is a **read-only** operator check: load the catalog and every secret entry the way `sync` would, without creating a KEK, writing a catalog snapshot, or sealing `.hev` bundles.

Use it in CI or before a production sync to catch missing SSM parameters, oversize values, invalid env lines, and (when configured) missing S3 document keys.

## CLI

Same config resolution as `sync` (`--config`, `HOST_ENV_VAULT_CONFIG`, `[sync]` table, `--source ssm|local`, `catalog_param`, `secrets_prefix`, `local_secrets_dir`, optional `s3_bucket` / `s3_prefix`).

```bash
host-env-vault validate
host-env-vault validate --profile app-web
host-env-vault validate --source local --local-secrets-dir ./dev-shared/secrets
```

Exit code is non-zero when any profile fails. Stdout prints one success line per profile; stderr summarizes failures (missing parameter, oversize body, catalog/manifest errors).

## Per-app manifest (optional v2)

Application repos can carry a small manifest listing the secrets **they expect**, separate from the host catalog. Validate can cross-check manifest names against the catalog allowlist when you pass `--manifest PATH`.

Example `.host-env-vault.toml` in an app repo:

```toml
profile = "app-web"

[inject]
env = ["DB_PASS", "SESSION_SECRET"]
files = []

[runtime]
env = []
files = []
```

Semantics today:

- **Error** if a manifest name is not allowed for that profile in the catalog (`inject` / `runtime` env and file lists).
- **Warn** (log) if the catalog lists an entry the manifest omits — the host catalog remains authoritative; the manifest is an app-side checklist, not a second source of truth.

Future work: optional `compose_service` field, validating document keys, and CI hooks that run `validate --manifest` on every app PR.

See also [compositional catalog](compositional-catalog.md) for how profile fragments merge before sync.
