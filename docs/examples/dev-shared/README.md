# Shared local dev (multi-app, one vault)

**Tracked copy for bootstrapping only.** Copy or let `./scripts/local-shared-bootstrap.sh` seed `dev-shared/` at the repo root (that directory is gitignored and holds your real catalog fragments and secrets).

One **host agent state** on a laptop can serve several application repos. Each app only mounts **rendered** secret directories (or runtime sockets); apps do not run their own vault.

## Layout

```text
dev-shared/
  host-config.toml          # from host-config.toml.example (gitignored when created)
  catalog.d/                # compositional profile fragments (one file per downstream app)
    10-example-web-stack.json
    20-example-api-stack.json
  build/catalog.json        # merged (generated)
  secrets/                  # gitignored — values + generated catalog.json
  secrets.example/          # copy templates
  state/                    # gitignored — .hev bundles
  run/                      # gitignored — render output
  kek.age                   # gitignored
```

## Compositional catalog

The agent reads **one** merged catalog per sync. Source fragments live in `catalog.d/` so each application team can version and ship its own JSON file independently. Run `scripts/merge-catalog.sh` before sync (or use `scripts/local-shared-sync.sh`).

See [docs/compositional-catalog.md](../docs/compositional-catalog.md).

## Quick start

```bash
chmod +x scripts/*.sh
./scripts/local-shared-bootstrap.sh
```

Edit `dev-shared/secrets/*.env` and files under `dev-shared/secrets/files/`.

Point every app at the same config:

```bash
export HOST_ENV_VAULT_CONFIG="/absolute/path/to/host-env-vault/dev-shared/host-config.toml"
```

## Render examples

```bash
host-env-vault render --profile app-web --dest dev-shared/run/app-web/current
host-env-vault render --profile api-http --dest dev-shared/run/api-http/current
```

Mount each `current/` tree read-only in compose at `/run/secrets`.

## macOS notes

- Build the agent for your architecture (`cargo build --release`).
- For profiles with **runtime** lists, local dev may put those keys in the profile `.env` until `serve` + container UID mapping is configured.
