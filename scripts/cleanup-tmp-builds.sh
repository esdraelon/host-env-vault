#!/usr/bin/env bash
# Remove stale host-env-vault and hev Cargo target trees from /tmp (safe to re-run).
set -euo pipefail

shopt -s nullglob
removed=0
for pattern in /private/tmp/host-env-vault-target* /private/tmp/hev-target /tmp/host-env-vault-target* /tmp/hev-target; do
  for path in $pattern; do
    [[ -e "$path" ]] || continue
    rm -rf "$path"
    echo "removed $path"
    removed=$((removed + 1))
  done
done

if [[ "$removed" -eq 0 ]]; then
  echo "no matching build dirs under /tmp"
fi

du -sh /private/tmp 2>/dev/null || true
