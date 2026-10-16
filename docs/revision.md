# Revision plan (post–M9)

This document tracks product hardening after the initial milestone stack: operator-friendly docs, local development without AWS, and removing baked-in assumptions from code and tests.

## Goals

1. **Documentation** — README oriented to daily use; language examples for inject and runtime clients.
2. **Development mode** — Sync secrets from local files (`.env` per profile) instead of SSM, without changing render/serve behavior.
3. **Configuration-driven** — No org-specific paths, profile names, or CLI integrations in core logic; sensible defaults only.
4. **systemd installer** — One command to install unit files, enable sync timer, and register runtime `serve` instances.
5. **Profile setup wizard** — Interactive shell script: ensure the binary is installed, then walk through AWS and the first catalog profile.

## Current state (after path defaults change)

| Item | Status |
| --- | --- |
| Catalog default parameter | `/host-env-vault/profiles` |
| Secret parameter layout | `{secrets_prefix}/{profile}/{entry}`; default prefix `/host-env-vault` |
| CLI | `sync --catalog-param`, `sync --secrets-prefix` |
| Render / serve | Read local `.hev` only; no AWS |
| Legacy | `ProfileId` enum, `seal` staging, `hydrate gh` still present |

## M10 — Secret source port

**Problem.** `application/sync` is tightly coupled to `SsmPort` for catalog and entries. Dev mode and future backends (Vault, 1Password CLI, files) need the same seal pipeline.

**Design.**

```text
ports/secret_source.rs
  trait SecretSource {
    fn load_catalog(&self) -> Result<String, Error>;
    fn load_entry(&self, profile: &str, entry: &str) -> Result<String, Error>;
  }

  SsmSecretSource { catalog_param, secrets_prefix, ssm: &dyn SsmPort }
  LocalSecretSource { root: Path }   // M11
```

- `sync_from_ports` takes `&dyn SecretSource` (or enum `SyncBackend`) instead of calling `ssm.get_parameter` directly.
- Catalog snapshot on disk unchanged (`catalog.json`).
- Unit tests keep `MemorySsm` behind `SsmSecretSource`.

**Acceptance.** All existing sync tests pass; no behavior change for production SSM sync.

- [x] **M10** `stack/m10-secret-source-port` — Secret source port; sync pulls catalog and entries through `SecretSource`.

### M10 completion

- Branch: `stack/m10-secret-source-port`
- Commit: `9f31efbf17de1243219f141e509f3244fd5fe5e1`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m10 cargo test` (201 tests, full suite) — passed; line coverage **95.55%** on `src/` (`cargo llvm-cov --lib`, `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m10-cov`, `LLVM_COV` / `LLVM_PROFDATA` from Homebrew llvm); `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m10-mutants cargo mutants --file src/ports/secret_source.rs --file src/application/sync/mod.rs` — **31/32 caught (96.9%)** on M10 scope (41 mutants, 9 unviable, 1 missed: `write_bundle_atomically` empty-parent guard).
- [`SecretSource`](src/ports/secret_source.rs) + [`SsmSecretSource`](src/ports/secret_source.rs); [`sync_from_secret_source`](src/application/sync/mod.rs) drives catalog/entry fetch; [`sync_from_ports`](src/application/sync/mod.rs) / [`sync_from_ssm`](src/application/sync/mod.rs) wrap SSM for unchanged CLI; `ssm_entry_parameter` lives on the port module; unit tests on `SsmSecretSource` with [`MemorySsm`](src/ports/ssm.rs).
- No new tracing branches; existing `sync` log_tests unchanged.

## M11 — Development mode (local `.env`)

**Operator story.** On a laptop, create:

```text
dev-secrets/
  catalog.json          # same shape as SSM catalog (or symlink)
  app-web.env           # KEY=value lines + optional file refs (see below)
  app-worker.env
```

**CLI.**

```bash
host-env-vault sync \
  --source local \
  --local-secrets-dir ./dev-secrets \
  --identity ./dev/kek.age \
  --state-dir ./dev/state
```

**Semantics.**

- **Catalog** — Read `catalog.json` from `local-secrets-dir` (not SSM). Still write snapshot into `state_dir` so render/serve match production.
- **Entries** — For each name in the profile lists, read from `app-web.env`:
  - Env entries: line `NAME=value` (same rules as rendered `secrets.env`).
  - File entries: either `NAME=@relative/path` pointing to a file under the dir, or a sibling file `files/NAME` (pick one convention in implementation; document in README).
- **No AWS** — `sync --source local` must not call the SDK.
- **S3 documents** — Optional `--s3-bucket` unchanged; local dev can skip documents or add plain files under `dev-secrets/files/`.

**Acceptance.** Integration test: local dir → sync → render → assert `secrets.env`; serve runtime entry over socket.

- [x] **M11** `stack/m11-sync-local` — Local `SecretSource`, `sync --source local`, integration test.

### M11 completion

- Branch: `stack/m11-sync-local`
- Commit: `4abeaf7e73cee800782b296faf4efe018fd6debc`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m11 cargo test` — **207** tests passed; `RUST_TEST_THREADS=1 CARGO_TARGET_DIR=/tmp/host-env-vault-target-m11-mutants cargo mutants --file src/ports/secret_source.rs --file src/application/sync/mod.rs` — **49/50 caught (98.0%)** on viable mutants (60 total, 10 unviable; 1 missed: pre-existing `write_bundle_atomically` empty-parent guard).
- [`LocalSecretSource`](src/ports/secret_source.rs): `catalog.json`, `{profile}.env`, file entries via `files/NAME` or `NAME=@relative/path`; [`sync_from_local`](src/application/sync/mod.rs); CLI `--source ssm|local` (default `ssm`), `--local-secrets-dir`; integration test `local_sync_render_and_serve_without_aws`.
- File-entry convention documented in README local dev section.

## M12 — Configuration file

Reduce repeated flags in systemd and dev scripts.

```toml
# /etc/host-env-vault/config.toml (example)
identity = "/etc/host-env-vault/kek.age"
state_dir = "/var/lib/host-env-vault"
runtime_dir = "/run/host-env-vault"

[sync]
source = "ssm"   # or "local"
catalog_param = "/host-env-vault/profiles"
secrets_prefix = "/host-env-vault"
local_secrets_dir = "/etc/host-env-vault/dev"  # when source = local
# s3_bucket = "..."
# s3_prefix = "recovery/"
```

- Precedence: CLI flags override file; file overrides defaults.
- Single config path via `HOST_ENV_VAULT_CONFIG` or `--config`.

- [x] **M12** `stack/m12-config-file` — TOML config file, merge precedence, CLI wiring.

### M12 completion

- Branch: `stack/m12-config-file`
- Commit: `c64ed7e84f5edc907d928a00c97ccd392b7b68e0`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m12 cargo test` — **222** tests passed; `RUST_TEST_THREADS=1 CARGO_TARGET_DIR=/tmp/host-env-vault-target-m12 cargo mutants --file src/config/mod.rs` — **11/11 caught (100%)** on viable mutants (14 total, 3 unviable).
- [`config`](src/config/mod.rs): load `/etc/host-env-vault/config.toml` or `HOST_ENV_VAULT_CONFIG` / `--config`; `[sync]` fields; merge helpers with CLI > file > defaults; `sync` / `render` / `serve` in [`main.rs`](src/main.rs) resolve paths from file when flags omitted; README configuration section.
- Tests: `config/behavior_tests` (parse, load missing file, path resolution, sync/render/serve merge precedence).

## M13 — Neutral naming in tests and legacy cleanup

- Replace `denarius-*` fixture profile names with `app-web`, `app-worker`, `edge-proxy`.
- Move `ProfileId` enum and `seal` subcommand to `legacy` only; remove Denarius/IDP references from crate docs and clap `about`.
- **`hydrate gh`** — Generalize to `hydrate tool` driven by catalog extension (tool name, profile, entry mapping) or move to a separate optional binary so core stays generic.

- [x] **M13** `stack/m13-neutral-fixtures` — Neutral catalog fixture names in tests; generic hydrate users; crate description cleanup.

### M13 completion

- Branch: `stack/m13-neutral-fixtures`
- Commit: `3271745`
- Gates: `./scripts/gate.sh test` — **225** tests passed; per-file `./scripts/gate.sh mutants -- --file …` on all touched `.rs` modules — **311/357 caught (87.1%)** on viable mutants (44 unviable; `catalog/load.rs` and `testing/mutation_closeout.rs` have no production mutants in scope).
- Catalog-driven tests use `app-web`, `app-worker`, and `edge-proxy` instead of `denarius-*`; GitHub hydrate tests use generic `gh-user-alpha` / `gh-user-beta`; [`Cargo.toml`](Cargo.toml) description and [`legacy/profile`](src/legacy/profile.rs) docs no longer name a specific product. Legacy [`ProfileId`](src/legacy/profile.rs) enum variants kept; `as_str()` aligned to neutral names; `hydrate gh` / `seal` CLI generalization deferred to a later milestone.

## M14 — Unit templates

Ship maintained templates under `packaging/systemd/` (not a live install yet):

| Unit | Role |
| --- | --- |
| `host-env-vault-sync.service` | Oneshot `sync` |
| `host-env-vault-sync.timer` | Hourly (or daily) trigger |
| `host-env-vault-serve@.service` | Template: `serve --profile %i` |

- Units use `EnvironmentFile=-/etc/host-env-vault/env` for `AWS_REGION` and optional static config path once M12 lands.
- Align `ExecStart` with current CLI (`--profile` on `serve`, all required paths).
- README daily-driver section references these filenames.

**Acceptance.** Templates pass `systemd-analyze verify` when installed on a Linux host; no behavior change to the Rust binary.

- [x] **M14** `stack/m14-systemd-templates` — systemd unit templates under `packaging/systemd/`.

### M14 completion

- Branch: `stack/m14-systemd-templates`
- Commit: `4b85620`
- Gates: no Rust changes; `systemd-analyze verify packaging/systemd/*.service` — **skipped on macOS** (`systemd-analyze` not installed); run on Linux after copy to `/etc/systemd/system/` per acceptance above.
- Added [`host-env-vault-sync.service`](packaging/systemd/host-env-vault-sync.service), [`host-env-vault-sync.timer`](packaging/systemd/host-env-vault-sync.timer), [`host-env-vault-serve@.service`](packaging/systemd/host-env-vault-serve@.service): `EnvironmentFile=-/etc/host-env-vault/env`, `ExecStart` uses current CLI (`sync`; `serve --profile %i`) with paths from default/`HOST_ENV_VAULT_CONFIG` config file (M12). Removed stale [`packaging/host-env-vault.service`](packaging/host-env-vault.service). README daily driver points at `packaging/systemd/` filenames.

## M15 — systemd service installer

**Deliverable.** `scripts/install-systemd.sh` (or `host-env-vault install systemd` thin wrapper) run as root on the host.

**Behavior.**

1. **Preflight** — Linux + systemd; `host-env-vault` on `PATH` (or `--binary` override); config/env file exists or installer writes defaults under `/etc/host-env-vault/`.
2. **Install units** — Copy M14 templates into `/etc/systemd/system/`, substitute paths (`identity`, `state_dir`, `runtime_dir`, binary path) from config file or flags.
3. **Sync timer** — `daemon-reload`, `enable --now host-env-vault-sync.timer` (interval flag: `--on-calendar hourly` default).
4. **Runtime profiles** — Read local `catalog.json` snapshot or ask for profile names; for each profile with `socket: true`, `enable host-env-vault-serve@<name>.service` (skip already enabled).
5. **Dry run** — `--dry-run` prints paths and `systemctl` commands without writing.
6. **Uninstall** — `--uninstall` disables timer and serve instances, removes unit files, reloads daemon.

**Non-goals.** Does not create IAM roles, SSM parameters, or the age identity (wizard or first `sync` does).

**Acceptance.** Documented in README; manual test checklist: fresh VM → install binary → run installer → timer active → optional serve@ starts.

**Depends on.** M14 templates; M12 recommended so installer reads one config file instead of many flags.

- [x] **M15** `stack/m15-systemd-installer` — `scripts/install-systemd.sh` copies units, enables timer and serve@ instances.

### M15 completion

- Branch: `stack/m15-systemd-installer`
- Commit: branch tip (`git log -1 --oneline` on `stack/m15-systemd-installer`)
- Gates: `shellcheck scripts/install-systemd.sh`; `./scripts/install-systemd.sh --dry-run --binary /bin/sh --profile app-worker`; `test ! -d /tmp/hev-target` (no Rust changes).
- [`scripts/install-systemd.sh`](scripts/install-systemd.sh): root preflight, `--dry-run`, `--uninstall`, path/binary substitution from config or flags, sync timer enable, serve@ from `catalog.json` snapshot or `--profile`. README systemd section documents installer and manual QA checklist (fresh VM → binary → installer → timer active → optional serve@).

## M16 — Profile setup wizard (shell)

**Deliverable.** `scripts/setup-profile.sh` (invoked as `./scripts/setup-profile.sh` or installed as `host-env-vault-setup`).

**Goal.** Operator with **admin AWS credentials** (can `ssm:PutParameter`) gets from zero to “catalog updated, secrets created, first sync succeeded” without hand-editing JSON.

### Phase A — Binary and host layout

1. If `host-env-vault` missing from `PATH`:
   - Detect `cargo` + source tree (repo root via script location) → `cargo build --release` and `install` to `/usr/local/bin` (or `~/.local/bin` with prompt).
   - Else print install instructions (release tarball URL when published) and exit non-zero.
2. Create `/etc/host-env-vault`, `/var/lib/host-env-vault`, `/run/host-env-vault` with safe modes (sudo when needed).
3. Optional: offer to run M15 installer at the end.

### Phase B — AWS

1. Prompt for `AWS_REGION` / `AWS_DEFAULT_REGION`.
2. Optional `AWS_PROFILE` (export for subshell commands).
3. Verify with `aws sts get-caller-identity` (require AWS CLI v2 installed; document dependency).
4. Prompt for catalog parameter and secrets prefix (defaults from M10 constants).
5. Show minimal IAM policy snippet for **host** role (GetParameter) vs **operator** role (PutParameter for wizard only).

### Phase C — Profile definition

Interactive prompts (validate against catalog rules: name charset, socket ⇒ `require_uid`):

| Step | Prompt |
| --- | --- |
| Profile name | e.g. `app-web` |
| Delivery | inject only / runtime only / both |
| Inject env names | comma-separated or loop until empty |
| Runtime env names | if applicable |
| File entries | inject and/or runtime file basenames |
| `require_uid` | if runtime or socket |
| `gid` | optional, for render modes |

Build JSON fragment; merge into full catalog:

- If catalog parameter **missing** → create new `{"profiles":[…]}`.
- If **exists** → fetch, parse, append or replace same `name` with confirm.

Use `aws ssm put-parameter` (SecureString) for catalog and each `{prefix}/{profile}/{entry}`.

### Phase D — Secret values

For each entry name, prompt to enter value (hidden read) or **skip** (parameter created empty / placeholder — document that sync fails until filled, or wizard only creates parameters when value provided).

### Phase E — First sync

Run:

```bash
host-env-vault sync --identity … --state-dir … [--catalog-param …] [--secrets-prefix …]
```

Report success, bundle paths, and next steps:

- inject → example `render` + compose mount line
- runtime → socket path + enable `serve@` via M15

**Flags.** `--non-interactive` with env vars or answers file (for CI smoke tests of the script logic only).

**Non-goals.** Not a TUI in Rust; no long-lived daemon; no replacement for SSM rotation workflows.

**Acceptance.**

- Shellcheck-clean script checked into repo.
- README “Daily driver” links to wizard as recommended first-time path.
- Test: mock `aws` stub in `scripts/tests/` or documented manual QA checklist (full AWS integration test optional in CI).

**Depends on.** Stable defaults (done); M10+ optional for local-only wizard path (M11: “dev profile” branch in wizard). M12 lets wizard write `/etc/host-env-vault/config.toml` for M15.

## Application examples (README)

Delivered in README section **Using secrets in your app** (Python, PHP, TypeScript):

- **Inject** — Parse `secrets.env` or load a file from `files/`.
- **Runtime** — Unix socket client with opcodes `1` (env) / `2` (file), 2000 ms lease; handle denied status.

No separate SDK crate until protocol stabilizes; copy-paste helpers are enough for v1.

## Open questions

- Should local dev support **only** `.env` per profile, or also a single merged `.env` with prefixed keys (`APP_WEB__DB_PASS`)?
- Customer-managed KMS for SSM: document only, or first-class catalog field?
- Multi-host identity: recovery when `kek.age` is lost (always re-seal from source; document backup policy for identity separately from bundles).

## Suggested branch order

```text
stack/m10-secret-source-port
stack/m11-sync-local
stack/m12-config-file
stack/m13-neutral-fixtures
stack/m14-systemd-templates
stack/m15-systemd-installer
stack/m16-profile-wizard
```

Each Rust milestone: implement → `scripts/gate.sh` → mutation on touched files only → cleanup (automatic). M14–M16 are mostly `packaging/` and `scripts/`; gate is shellcheck, template verify, and documented manual QA (no mutation gate on shell).

### Disk / gates (all Rust milestones M10+)

Use **one** disposable target dir; do **not** create `/tmp/host-env-vault-target-mNN*` trees.

```bash
# Full suite
./scripts/gate.sh test

# Scoped mutants (required — pass every touched .rs module)
./scripts/gate.sh mutants -- --file src/config/mod.rs

# Or test + mutants in one invocation
./scripts/gate.sh full -- --file 'src/foo/*.rs' --file src/bar/mod.rs
```

`scripts/gate.sh` sets `CARGO_TARGET_DIR=/tmp/hev-target` (override with `HEV_TARGET_DIR`), runs with `RUST_TEST_THREADS=1`, and **deletes the target dir and `mutants.out` on exit**. After a failed gate, fix and re-run; no manual `/tmp` janitor unless something crashed outside the script.

Optional: `./scripts/cleanup-tmp-builds.sh` removes legacy `/tmp/host-env-vault-target*` directories.

Orchestrator workers **must** use `scripts/gate.sh` for test/mutants gates and confirm `/tmp/hev-target` is gone when finished (`test ! -d /tmp/hev-target`).

### Milestone gates (M14–M16)

| Milestone | Gate |
| --- | --- |
| M14 | `systemd-analyze verify packaging/systemd/*.service` |
| M15 | Installer `--dry-run` in CI; checklist on Linux VM |
| M16 | `shellcheck scripts/setup-profile.sh`; optional stub-`aws` test |

## Relationship to `docs/plan.md`

M0–M9 in `docs/plan.md` are **complete** (core agent). This file is the **stacked continuation** (M10+). When a milestone merges, add a completion block to `docs/plan.md` the same way as M1–M9.
