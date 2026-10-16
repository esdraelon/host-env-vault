#!/usr/bin/env bash
# Merge compositional catalog fragments into one host-env-vault catalog document.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG_DIR="${HEV_CATALOG_DIR:-$REPO_ROOT/dev-shared/catalog.d}"
OUT="${1:-$REPO_ROOT/dev-shared/build/catalog.json}"

if [[ ! -d "$CATALOG_DIR" ]]; then
  echo "catalog dir missing: $CATALOG_DIR" >&2
  exit 1
fi

python3 - "$CATALOG_DIR" "$OUT" <<'PY'
import json
import sys
from pathlib import Path

catalog_dir = Path(sys.argv[1])
out_path = Path(sys.argv[2])

fragments = sorted(catalog_dir.glob("*.json"))
if not fragments:
    raise SystemExit(f"no *.json in {catalog_dir}")

profiles = {}
order = []
for path in fragments:
    doc = json.loads(path.read_text())
    for profile in doc.get("profiles", []):
        name = profile["name"]
        if name in profiles:
            raise SystemExit(f"duplicate profile {name!r} (also in earlier fragment)")
        profiles[name] = profile
        order.append(name)

merged = {"profiles": [profiles[n] for n in order]}
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(merged, indent=2) + "\n")
print(f"wrote {out_path} ({len(order)} profiles from {len(fragments)} fragments)")
PY
