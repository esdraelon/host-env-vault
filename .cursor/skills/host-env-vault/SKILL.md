---
name: host-env-vault
description: >-
  Operate and migrate host-env-vault: validate/sync, manifests, transition host
  stores (flat or SQLite), and posture assessment. Use when working in this repo,
  designing secret migration off compose plaintext, or wiring catalog profiles and SSM.
---

# host-env-vault

Host-side secret agent: **catalog allowlists** → **manifest preflight** → **validate/sync** from a `SecretSource` → sealed **`.hev`** → **render** (inject) / **serve** (runtime socket).

## When to use `validate` vs `sync`

| Situation | Command |
| --- | --- |
| CI, pre-deploy, or after editing catalog/SSM/manifests | **`validate`** — no `.hev` changes, no new KEK |
| Operator refresh after secrets changed upstream | **`sync`** — seals bundles; needs `--identity` when source requires decryption |
| Manifest missing or catalog/manifest mismatch | **`validate`** fails; **`sync`** keeps old `.hev`, writes `{profile}.stale` |
| After fixing parameters or manifests | **`validate`** first, then **`sync`** |

Use the **same** `--source`, paths, and manifest discovery for both commands.

## Security posture ladder (weakest → strongest at the app)

1. Plaintext in container / compose env (legacy — migrate away).
2. **Transition:** encrypted **host store** → `sync --source host-store` → `.hev` → render/serve.
3. **Target:** SSM (`sync --source ssm`) → same downstream.
4. Runtime-only secrets via **serve** socket where catalog marks `socket: true`.

Never recommend decrypt-and-vim. Secret writes: **`host-env-vault store`** subcommands or SSM/API only.

## CLI command graph (operator + generated migration scripts)

```text
store init → store put | store import
     ↓
write {profile}.env-host-vault (TOML names only; match catalog exactly)
     ↓
validate (--source …) → sync (--source …) → render | serve
     ↓
(later) store export --format ssm → validate --source ssm → sync --source ssm
```

Config: `/etc/host-env-vault/config.toml` or `HOST_ENV_VAULT_CONFIG`. Precedence: CLI > file > defaults.

### Top-level subcommands

| Command | Purpose |
| --- | --- |
| `validate` | Read-only: catalog + manifest preflight + every entry (+ optional S3 documents). |
| `sync` | Seal `.hev`; failed preflight keeps old bundle + `{profile}.stale`. |
| `render` | Inject lists to empty `--dest`; `ENV_HOST_VAULT_STALE` from `.stale` file. |
| `serve` | Runtime socket for allowlisted runtime entries. |

### `store` subcommands (transition mode)

| Command | Purpose |
| --- | --- |
| `store init` | Store layout + host age identity. |
| `store put` / `set` | Upsert entry; `--backend flat\|sqlite` when creating profile file. |
| `store get` | Masked read (`--show` for plaintext). |
| `store list` | Profiles and entry names. |
| `store remove` | Delete one entry. |
| `store import` | From dev dir or single env file. |
| `store rekey` | Re-encrypt all profile store files. |
| `store export` | SSM script or JSON manifest (`--format ssm`, `--dry-run`, `--json`). |

## Required per-profile manifest

File: **`{profile}.env-host-vault`** (TOML). **`[inject]`** and **`[runtime]`** env/file name sets must **exactly match** the catalog allowlists (strict equality).

Discovery (no `--manifest` unless CI escape hatch):

1. **`source = local`** and `{local_secrets_dir}/{profile}.env-host-vault` exists → use it.
2. Else `{manifests_dir}/{profile}.env-host-vault` (default `{state_dir}/manifests`).

Missing or mismatch → `validate` fails; `sync` does not replace that profile’s `.hev`.

Example shape (no secret values):

```toml
profile = "app-web"

[inject]
env = ["DB_PASS", "SESSION_SECRET"]
files = []

[runtime]
env = []
files = []
```

## Secret sources (`[sync] source`)

| Source | Use |
| --- | --- |
| `ssm` | Production target (Parameter Store). |
| `local` | Laptop: `catalog.json`, `{profile}.env`, `files/`, optional co-located manifests. |
| `host-store` | Encrypted per-profile files under `store_dir`; catalog from SSM or local `catalog.json`. |

**Store backend (per profile):** inferred from extension only — `{profile}.secrets.age` (flat) or `{profile}.secrets.db` (SQLite). Same host age KEK as `.hev`. Ambiguous or duplicate extensions → hard fail.

## Compositional catalog

Fragments in `dev-shared/catalog.d/` (gitignored locally); examples in `docs/examples/dev-shared/`. Merge with `scripts/merge-catalog.sh` before local sync. See [`docs/compositional-catalog.md`](../../../docs/compositional-catalog.md).

## Agent: assess an application directory (migration UX north star)

**In scope:** inspect layout, plan migration, **generate a script** that only invokes `host-env-vault` CLI.  
**Out of repo scope:** shipping that one-shot conversion script.

### Inspection checklist

1. Find compose/k8s env, `.env`, docker secrets, and mounted secret files.
2. Classify each name as **inject** (startup) vs **runtime** (socket/API).
3. Propose **profile name** and `{profile}.env-host-vault` listing those names (no values in manifest).
4. Check catalog fragment (or draft JSON) allowlists match manifest exactly.
5. Note posture step on ladder; recommend **host-store** (with `flat` vs `sqlite` per rotation needs) vs waiting for SSM.
6. Confirm manifests will live under `{manifests_dir}` on the host or beside local dev secrets.

### Script template the agent should emit

```bash
# Example shape — adjust paths; do not commit secrets or plaintext artifacts.
host-env-vault store init --store-dir /var/lib/host-env-vault/store --identity /etc/host-env-vault/kek.age
host-env-vault store import --profile APP_PROFILE --from-env-file ./extracted.env --non-interactive
# install manifests_dir/APP_PROFILE.env-host-vault (TOML names only)
host-env-vault validate --source host-store --identity /etc/host-env-vault/kek.age
host-env-vault sync --source host-store --identity /etc/host-env-vault/kek.age
host-env-vault render --profile APP_PROFILE --dest /run/host-env-vault/APP_PROFILE/current
```

After SSM is ready: `store export --format ssm --dry-run`, apply script, `validate --source ssm`, set `source = "ssm"`, `sync`, archive `store_dir` files. See [`docs/transition.md`](../../../docs/transition.md).

## Gates (this repo)

```bash
./scripts/gate.sh test
./scripts/gate.sh mutants -- --file src/path/to/module.rs
```

Docs-only milestones: no Rust gate; confirm `/tmp/hev-target` absent after any local `gate.sh` run.

## Docs map

- [`README.md`](../../../README.md) — posture ladder, CLI tables, daily driver
- [`docs/validate.md`](../../../docs/validate.md) — dry-run and manifests
- [`docs/transition.md`](../../../docs/transition.md) — store export and SSM cutover
- [`docs/compositional-catalog.md`](../../../docs/compositional-catalog.md) — fragments
- [`docs/revision.md`](../../../docs/revision.md) — M10+ roadmap
