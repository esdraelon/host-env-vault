# Crate layout

The library is layered so each directory maps to one architectural role. The binary (`src/main.rs`) parses CLI flags and wires **adapters** only.

```text
src/
  lib.rs                 public re-exports (stable API)
  main.rs                clap + adapter wiring

  core/                  errors, fixed-capacity slot table (Object Pool)
  vault/                 age KEK, HEV1 bundles, catalog seal/open
  catalog/               profile definitions, allowlist guards, SSM load
  ports/                 SsmPort, S3Port, GhPort (+ in-memory fakes)
  application/           use cases (Command pattern)
    sync/                SSM → sealed bundles
    documents/           S3 → document slots
    render/              bundle → tmpfs inject files
    serve/               bundle → runtime socket
    hydrate/             bundle → `gh auth`
    fetch_documents/     install hook for S3 keys
  legacy/                spike ProfileId enum, staging render, wire helpers
  adapters/              AWS SDK and process `gh` (binary-only)
  testing/               log capture, mutation closeout (#[cfg(test)])

packaging/               systemd unit
docs/plan.md             milestones and product plan
```

## Dependency direction

```text
  ports  ←  application  ←  catalog
              ↑
           vault, core
```

Application commands take **ports** as arguments in tests and from **adapters** in production. They never call the AWS SDK directly. Secrets live in **vault** ciphertext on disk and in **core** slots in memory.

## Slot indices (convention)

| Index | Command   |
| --- | --- |
| 0 | sync |
| 1 | render |
| 2 | serve |
| 3 | hydrate gh |

Only one profile occupies a slot at a time; see [plan.md](plan.md) for lease and sweep rules.

## Stable imports

External callers may keep using flat paths such as `host_env_vault::sync_from_ssm` and `host_env_vault::port::MemorySsm`. `lib.rs` re-exports them. Prefer `host_env_vault::ports` for new code.
