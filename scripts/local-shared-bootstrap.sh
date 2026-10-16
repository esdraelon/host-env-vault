#!/usr/bin/env bash
# First-time shared dev: copy examples, merge catalog, optional sync.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_SHARED="$REPO_ROOT/dev-shared"
SECRETS="$DEV_SHARED/secrets"

mkdir -p "$SECRETS/files"
if [[ ! -f "$DEV_SHARED/host-config.toml" ]]; then
  cat >"$DEV_SHARED/host-config.toml" <<EOF
identity = "$DEV_SHARED/kek.age"
state_dir = "$DEV_SHARED/state"
runtime_dir = "$DEV_SHARED/run"

[sync]
source = "local"
local_secrets_dir = "$SECRETS"
catalog_param = "/host-env-vault/profiles"
secrets_prefix = "/host-env-vault"
EOF
  echo "created dev-shared/host-config.toml (absolute paths under $DEV_SHARED)"
fi

for f in "$DEV_SHARED/secrets.example"/*.env; do
  base="$(basename "$f")"
  if [[ ! -f "$SECRETS/$base" ]]; then
    cp "$f" "$SECRETS/$base"
    echo "installed secrets/$base (edit with real dev values)"
  fi
done
for f in "$DEV_SHARED/secrets.example/files/"*; do
  [[ -e "$f" ]] || continue
  base="$(basename "$f")"
  if [[ ! -f "$SECRETS/files/$base" ]]; then
    cp "$f" "$SECRETS/files/$base"
    echo "installed secrets/files/$base"
  fi
done

export HOST_ENV_VAULT_CONFIG="$DEV_SHARED/host-config.toml"
"$REPO_ROOT/scripts/local-shared-sync.sh"
