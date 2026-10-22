# Transition mode → SSM migration

Host **transition mode** keeps secrets in encrypted per-profile files under `store_dir` (`{profile}.secrets.age`) while the catalog still lives in SSM or local `catalog.json`. When IAM and Parameter Store are ready, export store contents into SSM and flip `[sync] source` back to `ssm`.

## Export to SSM

Decrypt the host store with the same age identity used for `.hev` bundles, then emit migration artifacts:

```bash
host-env-vault store export --format ssm \
  --identity /etc/host-env-vault/kek.age \
  --store-dir /var/lib/host-env-vault/store \
  --secrets-prefix /host-env-vault
```

**Dry run** (paths and SHA256 only; no script body with values):

```bash
host-env-vault store export --format ssm --dry-run \
  --secrets-prefix /host-env-vault
```

**JSON manifest** (parameter names and SHA256 value references, no plaintext):

```bash
host-env-vault store export --format ssm --json \
  --secrets-prefix /host-env-vault > export-manifest.json
```

Default output is a **bash script** of `aws ssm put-parameter --type SecureString --overwrite` calls, one per `{secrets_prefix}/{profile}/{entry}`. Run it with credentials that have `ssm:PutParameter`. Limit to one profile with `--profile app-web`.

Config file `[sync] secrets_prefix` and `store_dir` apply when flags are omitted (same precedence as other subcommands).

## Cutover checklist

1. **Export** — `store export --format ssm` (use `--dry-run` first to verify paths and hashes).
2. **Load SSM** — run the generated script (or load parameters your own way using the JSON manifest hashes as a checksum guide).
3. **Validate** — `host-env-vault validate --source ssm` (manifest preflight still required; see [validate.md](validate.md)).
4. **Switch sync** — set `[sync] source = "ssm"` in config (or drop `--source host-store` from units) and run `sync`.
5. **Archive store** — after a successful sync from SSM, move or remove `{store_dir}/*.secrets.age` and `*.secrets.db` and document that transition mode is off.

Catalog parameter (`catalog_param`) is **not** exported by `store export`; update the catalog in SSM separately if profiles changed during transition.
