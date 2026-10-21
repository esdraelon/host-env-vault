---
name: host-env-vault
description: >-
  Operate and migrate host-env-vault: validate/sync, manifests, transition host
  stores, and posture assessment. Use when working in this repo, designing secret
  migration off compose plaintext, or wiring catalog profiles and SSM.
---

# host-env-vault

Host-side secret agent: **catalog allowlists** → **sync/validate** from a `SecretSource` → sealed **`.hev`** → **render** (inject) / **serve** (runtime socket).

## Security posture ladder (weakest → strongest at the app)

1. Plaintext in container / compose env (legacy — migrate away).
2. **Transition:** encrypted **host store** (M19+) → sync → `.hev` → render/serve.
3. **Target:** SSM (`sync --source ssm`) → same downstream.
4. Runtime-only secrets via **serve** socket where catalog marks `socket: true`.

Never recommend decrypt-and-vim. All secret writes go through **`host-env-vault store`** (M20+) or SSM/API.

## Commands (current and planned)

| Command | Purpose |
| --- | --- |
| `validate` | Read-only: catalog + every entry (+ manifest preflight). No `.hev` writes. |
| `sync` | Fetch secrets, seal `.hev`; failed preflight keeps old bundle + `{profile}.stale`. |
| `render` | Decrypt inject entries to dest; adds `ENV_HOST_VAULT_STALE` when `.stale` exists. |
| `serve` | Runtime socket for allowlisted runtime entries. |
| `store …` | **M20+** CRUD on encrypted host store (transition prod). |
| `store export` | **M21+** Prepare SSM migration. |

Config: `/etc/host-env-vault/config.toml` or `HOST_ENV_VAULT_CONFIG`. Precedence: CLI > file > defaults.

## Required per-profile manifest

File: **`{profile}.env-host-vault`** (TOML). Must **exactly match** catalog inject/runtime env and file name sets.

- Host: `{state_dir}/manifests/{profile}.env-host-vault` (or `[sync] manifests_dir`).
- Local dev: `{local_secrets_dir}/{profile}.env-host-vault`.

Missing or mismatch → `validate` fails; `sync` does not replace that profile’s `.hev`.

## Secret sources (`[sync] source`)

| Source | Use |
| --- | --- |
| `ssm` | Production target (Parameter Store). |
| `local` | Laptop: `catalog.json`, `{profile}.env`, `files/`. |
| `host-store` | **M19+** Per-profile encrypted files under `store_dir`. |
| (per-profile) | **M22+** Backend inferred from **store file extension** only (e.g. `.secrets.age` vs `.secrets.db`). |

Host store encryption uses the **same age identity as `.hev` / sync** (single host KEK).

`validate` must use the **same** source and manifest paths as `sync`.

## Compositional catalog

Fragments in `dev-shared/catalog.d/` (gitignored locally); examples in `docs/examples/dev-shared/`. Merge with `scripts/merge-catalog.sh` before local sync.

## Agent: assess an application directory (migration UX)

**In scope for agents:** inspect layout, plan migration, **generate a script** that only invokes `host-env-vault` CLI.  
**Out of repo scope:** shipping that one-shot conversion script.

### Inspection checklist

1. Find compose/k8s env, `.env`, docker secrets, and mounted secret files.
2. Classify each name as **inject** (startup) vs **runtime** (socket/API).
3. Propose **profile name** and `{profile}.env-host-vault` listing those names (no values in manifest).
4. Check catalog fragment (or draft JSON) allowlists match manifest exactly.
5. Note current posture step on ladder; recommend transition store vs waiting for SSM.

### Script template the agent should emit

```bash
# Example shape — adjust paths; do not commit secrets.
host-env-vault store init --store-dir /var/lib/host-env-vault/store
host-env-vault store import --profile APP_PROFILE --from ./path/to/extracted-env
# Write manifests_dir/APP_PROFILE.env-host-vault (TOML names only)
host-env-vault validate --source host-store ...
host-env-vault sync ...
host-env-vault render --profile APP_PROFILE --dest /run/...
```

After SSM is ready (M21): `store export --format ssm`, apply parameters, flip `source = "ssm"`, re-validate.

## Gates (this repo)

```bash
./scripts/gate.sh test
./scripts/gate.sh mutants -- --file src/path/to/module.rs
```

## Docs map

- [`README.md`](../../../README.md) — daily driver
- [`docs/validate.md`](../../../docs/validate.md) — dry-run
- [`docs/compositional-catalog.md`](../../../docs/compositional-catalog.md) — fragments
- [`docs/revision.md`](../../../docs/revision.md) — M10–M23 roadmap
