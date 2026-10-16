# host-env-vault implementation plan

The spike in this repo is exploratory. This document is the plan to build.

The agent is a Rust unix service. It has no TCP listener and no web UI. It installs as a systemd unit. Denarius and the IDP stay PHP. The agent is a separate binary so a bug in those apps is not a bug in the process that holds key material.

A profile is a process. PHP shares an address space, so a mode inside one process is not a boundary. Containers receive only the profile mounted or requested for that process.

## Storage

Three stores, with different jobs.

**Local vault.** The copy the host uses. One sealed bundle per profile under `/var/lib/host-env-vault/`. The bundle is `HEV1`: a fresh 32-byte data key, XChaCha20-Poly1305 over the entries, profile name as associated data. An age identity at `/etc/host-env-vault/kek.age` (mode `0400`) wraps the data key. The identity is generated on first sync and never uploaded. A new host mints a new identity and seals again from SSM.

**SSM Parameter Store.** The source of truth and the disaster-recovery copy. Standard `SecureString` parameters encrypted with the AWS-managed `aws/ssm` key. The agent polls once an hour and on `host-env-vault sync`. The instance role can `GetParameter` on `/amtgard/*` and cannot `PutParameter`. Operators write and rotate values with credentials the host does not have.

**S3.** Plain recovery files only: application env files and nginx site configs. No passwords, API keys, tokens, or key files. The bucket is versioned. The instance role can `GetObject` on that prefix and cannot write it.

```text
/amtgard/vault/profiles                         SecureString, the catalog
/amtgard/<profile>/<entry>                      SecureString, one secret each

s3://<bucket>/denarius.env
s3://<bucket>/idp.env
s3://<bucket>/nginx/<site>.conf
```

Bootstrap on the host is non-secret: region, catalog parameter name, S3 bucket and prefix, and local paths. It can live in the systemd unit.

If SSM is unreachable, sync leaves the last good bundles in place. A failed sync does not empty the vault. `render` and the socket read the local bundles and do not call SSM, so a deploy still works after a successful sync on this machine.

An hourly sync does not rewrite tmpfs files a container already has mounted. Those change on the next `render`.

## Catalog

The binary has no Denarius, IDP, or GitHub enum. The SSM catalog is the allowlist. A name that is not in a profile is not sealed and not served.

Each profile records:

- name
- which entries are injected at render
- which entries may be requested at runtime
- whether the profile has a unix socket
- peer uid expected on that socket
- optional gid for rendered files
- GitHub active user, only on the `github` profile
- document keys in S3, if any

Starting profiles, as catalog data rather than code:

| Profile | Injected | Runtime | Socket |
| --- | --- | --- | --- |
| `denarius-web` | `DB_PASS`, `IDP_CLIENT_SECRET`, `STRIPE_PUBLISHABLE_KEY` | none | no |
| `denarius-worker` | `DB_PASS`, `STRIPE_WEBHOOK_SECRET` | `STRIPE_SECRET_KEY`, `APP_KEY`, Teller files | yes |
| `denarius-connect` | `STRIPE_SECRET_KEY` | none | no |
| `idp-http` | provisional, until the HTTP process is traced | provisional | no |
| `idp-worker` | provisional | provisional | no |
| `github` | none | one token per account | no |
| `nginx` | none | none | no |

`idp-http` and `idp-worker` stay provisional in the catalog until `amtgardidpapp` and `jwt-pvh-worker.php` are traced. Overlap such as `oauth-private.key` is written explicitly in the catalog. A PEM or private key over 4096 bytes does not fit a standard `SecureString` and is rejected at sync.

`aws/ssm` allows decrypt for every principal in the account. Isolation on this host is the instance role’s parameter path plus the agent refusing to serve one profile’s entries on another profile’s socket. A customer-managed key is a later change if some other principal in the account must be unable to decrypt these values.

## Channels

**Render.** `install.sh` calls `render` before compose starts. The agent writes one profile into an empty directory on tmpfs. Secrets are files (`secrets.env` and `files/`), mode `0400`, or `0440` root:gid when `--gid` is set. Compose bind-mounts that directory read-only. A dirty destination is refused. `docker inspect` does not list the values.

**Socket.** One socket per profile that has a runtime list: `/run/host-env-vault/sockets/<profile>.sock`, mode `0600`, mounted only into that container. The path is the profile. The request names an entry on that profile’s runtime list. Peer uid is checked. There is no profile argument the client can change.

**Documents.** Plain S3 objects, including nginx site configs, land in document slots and then on the paths `install.sh` already uses. Certificates stay in the vault. Nginx config only points at those paths.

## GitHub

The vault does not implement a credential store. The `github` profile holds one token per account (`esdraelon`, `megiddo`, and any later account).

```text
host-env-vault sync
host-env-vault hydrate gh
```

`hydrate gh` runs `gh auth login --hostname github.com --with-token` once per token, then `gh auth switch --user <active>` from the catalog. `gh` writes its own keyring.

## Memory

Profiles on disk are uncapped. Memory holds four slots, one per thread. A request for a profile that is already in a slot runs on that thread. A request for any other profile waits until a thread can take it. That thread wipes the slot, then loads the profile from the local vault.

Each slot is fixed:

| Cap | Value |
| --- | --- |
| Secrets per profile | 32 |
| Secret bytes | 4096 |
| Documents per profile | 20 |
| Document bytes | 100 KB |
| Profile and entry names | 64 bytes |

A profile with more than 32 secrets or more than 20 documents is partitioned into two profiles and loaded one at a time. Ten nginx sites fit in one profile. Four full slots are about 8.5 MB.

Every copy checks the length first. Oversize input is rejected. Unused tails of the arrays stay zero. Secret bytes are these arrays and an explicit length. The commands do not grow a buffer to fit an SSM or S3 value.

## Lease

The lease is 2000 ms from the moment the profile is unpacked. The caller must finish in that window. At 2000 ms the slot is wiped, including when the in-use count is still set. That covers a holder that dies and never releases.

The owning thread wipes its slot when the lease expires. A sweep every two seconds wipes any slot whose lease is already older than 2000 ms. The wipe increments a generation. A late read or a late S3 write sees the new generation and drops its result instead of refilling the slot.

Sync uses the same slots. It seals one profile, wipes the slot, then starts the next. The hourly sync does not unpack the whole vault.

A longer lease for slow S3 waits until there is a measured time. The contract stays a fixed lease.

## Patterns

Four patterns, and no others.

- **Slot table.** Profiles, secrets, and documents.
- **Command.** `sync`, `render`, `serve`, `hydrate`.
- **Port.** SSM, S3, and `gh`. Tests mock the port. Commands only see slots.
- **Worker.** Four threads. A job is a profile name plus an entry or document index.

The daemon’s resident work is the hourly sync and the socket poll, using the four slots. `render` and `hydrate gh` are separate processes. Each has its own slot and the same lease.

## Work checklist

Resume from: (none — M0–M16 stack complete; see [revision.md](revision.md)). Gates: `./scripts/gate.sh`.

Gates for M1 onward: full `cargo test` (no filter), at least 95% line coverage of the crate, `cargo-mutants` at 80% on that milestone's scope, and a test that asserts the new decision-branch log lines on their own. This is not a Slim app. There is no benchmark gate.

Coverage command (Homebrew LLVM; use a dedicated `CARGO_TARGET_DIR`, not the same tree `cargo mutants` writes to):

```bash
export LLVM_COV=/opt/homebrew/Cellar/llvm/22.1.8/bin/llvm-cov
export LLVM_PROFDATA=/opt/homebrew/Cellar/llvm/22.1.8/bin/llvm-profdata
CARGO_TARGET_DIR=/tmp/host-env-vault-target-m01 cargo llvm-cov --lib --summary-only
```

Mutation command (library scope; `src/main.rs` excluded in `mutants.toml`). Prefer **`scripts/gate.sh`** so `/tmp/hev-target` is reused and removed on exit (see `docs/revision.md` disk/gates):

```bash
./scripts/gate.sh test
./scripts/gate.sh mutants -- --file 'src/application/sync/mod.rs'
```

- [x] **M0** `stack/m00-spike` — Record the uncommitted spike, README, packaging unit, and this plan. Hygiene only: do not start the slot table. `cargo test` must pass. Coverage and mutation gates are waived on this commit because M1 replaces the heap design.

### M0 completion

- Branch: `stack/m00-spike`
- Commit: `2e89927e0d7fd1bb6a2ae3ab6ce1d7389707d42c`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target cargo test` (full, no filter) — passed; coverage and `cargo-mutants` waived for M0.
- [x] **M1** `stack/m01-slot-table` — Slot table. Fixed arrays, lengths, wipe, and generation. Unit tests: oversize names and values are rejected, a wipe zeros the whole slot including unused tails, a stale generation cannot write back.

### M1 completion

- Branch: `stack/m01-slot-table`
- Commit: `3c7d71b0b13ac7a4fbabf67d1795fee9fa5112e1`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m01 cargo test` (54 tests, full suite) — passed; line coverage **95.93%** on `src/` (`cargo llvm-cov --lib`, see command above); `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m01-mutants cargo mutants --file src/slot.rs` — **66/81 caught (81.5%)** on M1 scope.
- Log-tested decision branches (separate `slot::log_tests` module): reject oversize name, reject oversize secret, reject oversize document, slot wipe, stale generation reject, sweep expired lease.
- Spike modules gained coverage-only tests where needed to hold the 95% crate gate; slot table is not yet wired into bundle/render/serve commands.
- [x] **M2** `stack/m02-catalog-port` — Catalog port. Load a profile definition into a slot from the SSM port. No application enum in the binary. Unit tests: an entry outside the catalog is refused.

### M2 completion

- Branch: `stack/m02-catalog-port`
- Commit: `46a236f3785eb3fe4d5c9fb2a4a9c10c377c2880`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m02 cargo test` (82 tests, full suite) — passed; line coverage **96.14%** on `src/` (`cargo llvm-cov --lib`); `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m02-mutants cargo mutants --file 'src/catalog/*.rs' --file src/port/ssm.rs` — **40/40 caught (100%)** on M2 scope (11 unviable).
- Log-tested decision branches (separate `catalog::log_tests` module): catalog parse failure, catalog refuse seal entry, catalog refuse serve entry, catalog refuse serve on non-socket profile.
- Spike `ProfileId` remains for legacy bundle/render/serve tests; catalog load, allowlist checks, and slot bind use string profile names from SSM JSON/TOML only.
- [x] **M3** `stack/m03-local-bundle` — Local bundle. Seal and open one profile through a slot. The age identity stays on the host. Unit tests: a relabeled profile name does not decrypt, a tampered ciphertext does not open.

### M3 completion

- Branch: `stack/m03-local-bundle`
- Commit: `e107c5d594a933833266f9e27d773da2bbb5a1ea`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m03 cargo test` (100 tests, full suite) — passed; line coverage **96.40%** on `src/` (`cargo llvm-cov --lib`); `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m03-mutants cargo mutants --file src/bundle.rs --file src/local_bundle/mod.rs` — **88/99 caught (88.9%)** on M3 scope (11 unviable).
- Log-tested decision branches (separate `local_bundle::log_tests` module): local bundle seal from slot, local bundle open into slot, local bundle refuse open not in catalog, local bundle refuse open entry.
- `seal_profile_in_slot` / `open_profile_into_slot` validate against the catalog allowlist, load one profile into a fixed slot, and emit `HEV1` bundles via unchanged age KEK wrap; legacy `ProfileId` CLI seal/open keeps spike policy checks on `open`.
- [x] **M4** `stack/m04-sync` — Sync command. Pull the catalog and each secret, seal bundles, and keep the previous bundle when the pull fails. Integration test with a fake SSM: success replaces the bundle, a failed refresh leaves the previous bytes, and only one profile occupies a slot at a time.

### M4 completion

- Branch: `stack/m04-sync`
- Commit: `1014242b8b7a740de1d9a887db12048ece0b7dbd`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m04 cargo test` (121 tests, full suite) — passed; line coverage **95.55%** on `src/` (`cargo llvm-cov --lib`); `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m04-mutants cargo mutants --file 'src/sync/*.rs'` — **25/26 caught (96.2%)** on M4 scope (7 unviable, 1 missed: empty-parent guard in atomic write).
- Log-tested decision branches (separate `sync::log_tests` module): sync catalog loaded and bundle replaced, sync profile failed keeping bundle, sync reject oversize parameter, sync created host identity on first run.
- `sync` CLI subcommand (`--identity`, `--state-dir`, `--catalog-param`) calls AWS SSM via SDK in `main`; library integration tests use `MemorySsm`. Pulls `/amtgard/<profile>/<entry>`, seals through slot 0, atomically replaces `<profile>.hev`, mints age identity when missing.
- [x] **M5** `stack/m05-render` — Render command. Write an empty destination from the local bundle. Integration test: file modes, refusal of a dirty destination, and no call to the SSM port.

### M5 completion

- Branch: `stack/m05-render`
- Commit: `35b98cef1b55b0cbbadf697a6ffc8f7bee62b6cc`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m05 cargo test` (136 tests, full suite) — passed; line coverage **95.38%** on `src/` (`cargo llvm-cov --lib`); `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m05-mutants cargo mutants --file 'src/render_cmd/*.rs' --file src/catalog/local.rs` — **13/14 caught (92.9%)** on M5 scope (4 unviable, 1 missed: empty-parent guard in catalog snapshot write).
- Log-tested decision branches (separate `render_cmd::log_tests` module): render inject-only skipping runtime entries, render wrote inject destination, render refuse profile not in catalog, render does not skip when all entries are inject (negative log check); local bundle open during render reuses existing log line.
- Sync persists `catalog.json` beside bundles; `render` CLI uses `--profile`, `--identity`, `--state-dir`, `--dest`, optional `--gid` override. Opens `.hev` through slot 1, filters catalog inject lists, refuses non-empty dest, no SSM at render time.
- [x] **M6** `stack/m06-serve` — Serve command. One socket per runtime profile. The request names an entry. The lease wipes the slot at 2000 ms. Integration test: a peer uid mismatch is denied, a name from another profile is denied, and a request that overruns the lease observes a wiped slot.

### M6 completion

- Branch: `stack/m06-serve`
- Commit: `23378c5c6228998c52834504adc10a38ff7cdf90`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m06 cargo test` (158 tests, full suite) — passed; line coverage **95.38%** on `src/` (`cargo llvm-cov --lib`); `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m06-mutants cargo mutants --file 'src/serve_cmd/*.rs' --file src/serve.rs` — **48/59 caught (81.4%)** on M6 scope (19 unviable, 11 missed).
- Log-tested decision branches (separate `serve_cmd::log_tests` module): serve deny runtime entry (catalog refuse inject name), serve returned runtime entry, serve refuse profile without socket, serve deny peer uid.
- Refactored spike `serve.rs` to entry-name frames and wire I/O; new `serve_cmd` opens local `.hev` bundles through serve slot 2 under the 2000 ms lease with idle sweep, catalog `require_uid`, and `poll_serve_once` for tests. CLI `serve` takes `--profile` and uses catalog peer uid (no SSM at serve time).
- [x] **M7** `stack/m07-s3-documents` — S3 port. Fill document slots, including nginx site files. Integration test with a fake S3: a file over 100 KB is rejected, and a secret-shaped object is not accepted on this port.

### M7 completion

- Branch: `stack/m07-s3-documents`
- Commit: `68809de472e0a0ba20114306e17eb7fea2cfc4e4`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m07 cargo test` (182 tests, full suite) — passed; line coverage **95.41%** on `src/` (`cargo llvm-cov --lib`, dedicated `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m07-cov`); `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m07-mutants cargo mutants --file 'src/port/s3.rs' --file 'src/documents/mod.rs' --file 'src/fetch_documents_cmd/mod.rs' --file 'src/sync/mod.rs' --file 'src/catalog/parse.rs'` — **116/118 caught (98.3%)** on M7 scope (8 unviable, 2 missed: `is_secret_shaped_s3_key` guard mutations).
- Log-tested decision branches (separate `documents::log_tests` and `fetch_documents_cmd::log_tests` modules): documents reject oversize s3 object, documents reject secret-shaped s3 key, documents loaded s3 object, fetch documents refuse profile not in catalog.
- [`S3Port`](src/port/s3.rs) + [`MemoryS3`](src/port/s3.rs); catalog `documents` keys (including `nginx/*.conf`) load into document slots; secret-shaped keys and bodies over 100 KB refused; [`sync_from_ports`](src/sync/mod.rs) optional S3 prefix during sync; CLI `fetch-documents` and sync `--s3-bucket` / `--s3-prefix` hooks.

- [x] **M8** `stack/m08-hydrate-gh` — GitHub hydrate. Feed each token slot to `gh auth login --with-token`, then switch the active user. Integration test with a fake `gh` that records stdin and the switch user.

### M8 completion

- Branch: `stack/m08-hydrate-gh`
- Commit: `c6112a5`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m08 cargo test` (194 tests, full suite) — passed; line coverage **95.41%** on `src/` (`cargo llvm-cov --lib`, dedicated `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m08-cov`); `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m08-mutants cargo mutants --file src/port/gh.rs --file 'src/hydrate_cmd/*.rs'` — **15/15 caught (100%)** on M8 scope (3 unviable).
- Log-tested decision branches (separate `hydrate_cmd::log_tests` module): hydrate refuse profile not in catalog, hydrate refuse missing github active user, hydrate gh logged in account, hydrate gh switched active user.
- [`GhPort`](src/port/gh.rs) + [`MemoryGh`](src/port/gh.rs); `hydrate gh` CLI opens local `github.hev` through hydrate slot 3, feeds each catalog runtime token to `gh auth login --with-token`, then `gh auth switch --user` from `github_active_user`; production [`ProcessGh`](src/main.rs) wraps the real CLI.
- [x] **M9** `stack/m09-mutation` — Mutation closeout. `cargo-mutants` at 80% across the library (see mutation command above). The mutations that must be caught are the bounds checks, the wipe, the generation, the profile mismatch, the lease expiry, and the keep-the-last-bundle path. Fill any gaps the earlier milestones left.

### M9 completion

- Branch: `stack/m09-mutation`
- Commit: `30a944913725a806b38b27386c9d9c3630d35656`
- Gates: `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m09 cargo test` (199 tests, full suite) — passed; line coverage **95.73%** on `src/` (`cargo llvm-cov --lib`, dedicated `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m09-cov`); `CARGO_TARGET_DIR=/tmp/host-env-vault-target-m09-mutants cargo mutants -- -- --test-threads=1` — **411/467 caught (88.0%)** on library scope (549 mutants, 82 unviable, 51 missed, 5 timeouts; `src/main.rs` excluded).
- Guard tests: `mutation_closeout` (bounds, wipe, generation, lease, keep-last-bundle); render/serve profile mismatch; document secret-shaped S3 keys; shared `log_test_capture` with `serial_test` on log modules.
- **All milestones M0–M9 on the stack are complete.**

## Later

- Trace which files the IDP HTTP process and `jwt-pvh-worker.php` open, then tighten those catalog entries.
- `USER www-data` in the images, with the catalog gid and peer uid set to match.
- A measured S3 lease, if 2000 ms is too short for document loads.
- A customer-managed KMS key, if another principal in the account must be unable to decrypt these parameters.
