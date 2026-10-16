#!/usr/bin/env bash
# One-shot local dev: merge catalog.d → secrets/catalog.json, then sync --source local.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_SHARED="${HEV_DEV_SHARED:-$REPO_ROOT/dev-shared}"
SECRETS_DIR="${HEV_SECRETS_DIR:-$DEV_SHARED/secrets}"
STATE_DIR="${HEV_STATE_DIR:-$DEV_SHARED/state}"
IDENTITY="${HEV_IDENTITY:-$DEV_SHARED/kek.age}"
CONFIG="${HOST_ENV_VAULT_CONFIG:-$DEV_SHARED/host-config.toml}"

BIN="${HOST_ENV_VAULT_BIN:-host-env-vault}"
if ! command -v "$BIN" >/dev/null 2>&1; then
  echo "building host-env-vault from $REPO_ROOT …" >&2
  (cd "$REPO_ROOT" && cargo build --release)
  BIN="$REPO_ROOT/target/release/host-env-vault"
fi

mkdir -p "$SECRETS_DIR" "$STATE_DIR" "$(dirname "$IDENTITY")"
"$REPO_ROOT/scripts/merge-catalog.sh" "$DEV_SHARED/build/catalog.json"
cp "$DEV_SHARED/build/catalog.json" "$SECRETS_DIR/catalog.json"

ARGS=(
  sync
  --source local
  --local-secrets-dir "$SECRETS_DIR"
  --identity "$IDENTITY"
  --state-dir "$STATE_DIR"
)
if [[ -f "$CONFIG" ]]; then
  ARGS+=(--config "$CONFIG")
fi

exec "$BIN" "${ARGS[@]}"
