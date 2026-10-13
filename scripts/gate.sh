#!/usr/bin/env bash
# Milestone gates with a single disposable CARGO_TARGET_DIR and cleanup on exit.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TARGET="${HEV_TARGET_DIR:-/tmp/hev-target}"
export CARGO_TARGET_DIR="$TARGET"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"

cleanup() {
  rm -rf "$TARGET"
  if [[ "${HEV_CLEAN_MUTANTS_OUT:-1}" == "1" ]]; then
    rm -rf "$REPO_ROOT/mutants.out"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage:
  scripts/gate.sh test
  scripts/gate.sh mutants -- [cargo mutants options, e.g. --file src/config/mod.rs]
  scripts/gate.sh full -- [cargo mutants options after --]

Uses one target dir (default /tmp/hev-target). Removed on exit.
Env:
  HEV_TARGET_DIR       override target path
  HEV_CLEAN_MUTANTS_OUT=0  keep mutants.out in repo root
  RUST_TEST_THREADS    default 1 (log-capture tests)

Do not create per-milestone /tmp/host-env-vault-target-* trees.
EOF
}

cmd="${1:-}"
shift || true

case "$cmd" in
  test)
    cargo test "$@"
    ;;
  mutants)
    if [[ "${1:-}" == "--" ]]; then
      shift
    fi
    if [[ $# -eq 0 ]]; then
      echo "gate.sh mutants: pass --file (or other cargo mutants args)" >&2
      exit 2
    fi
    cargo mutants "$@" -- -- --test-threads=1
    ;;
  full)
    cargo test
    if [[ "${1:-}" == "--" ]]; then
      shift
    fi
    if [[ $# -eq 0 ]]; then
      echo "gate.sh full: pass mutants scope after --" >&2
      exit 2
    fi
    cargo mutants "$@" -- -- --test-threads=1
    ;;
  -h | --help | help | "")
    usage
    exit 0
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    usage
    exit 2
    ;;
esac
