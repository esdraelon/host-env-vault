#!/usr/bin/env bash
# Smoke test setup-profile.sh with mock AWS (no real SSM, no sync binary required).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MOCK_BIN="$(mktemp -d)"
STATE="$(mktemp)"
trap 'rm -rf "$MOCK_BIN" "$STATE"' EXIT

chmod +x "$ROOT/scripts/tests/mock-aws"
ln -s "$ROOT/scripts/tests/mock-aws" "$MOCK_BIN/aws"
cat >"$MOCK_BIN/host-env-vault" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$MOCK_BIN/host-env-vault"
export PATH="$MOCK_BIN:$PATH"
export MOCK_AWS_STATE="$STATE"

export HEV_SETUP_AWS_REGION=us-east-1
export HEV_SETUP_PROFILE_NAME=app-web
export HEV_SETUP_DELIVERY=inject
export HEV_SETUP_INJECT_ENV=DB_PASS
export HEV_SETUP_SKIP_SYNC=1
export HEV_SETUP_SKIP_LAYOUT=1
export HEV_SETUP_BINARY="$MOCK_BIN/host-env-vault"

"$ROOT/scripts/setup-profile.sh" --non-interactive --dry-run

export HEV_SETUP_SECRET_VALUES="$ROOT/scripts/tests/fixtures/secret-values.json"
"$ROOT/scripts/setup-profile.sh" --non-interactive

python3 - "$STATE" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
params = data.get("parameters", {})
assert "/host-env-vault/profiles" in params
catalog = json.loads(params["/host-env-vault/profiles"])
names = [p["name"] for p in catalog["profiles"]]
assert "app-web" in names
assert "/host-env-vault/app-web/DB_PASS" in params
assert params["/host-env-vault/app-web/DB_PASS"] == "test-secret"
print("setup-profile smoke: ok")
PY
