#!/usr/bin/env bash
# Install host-env-vault systemd units from packaging/systemd/ (M15).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_DIR="$REPO_ROOT/packaging/systemd"
SYSTEMD_DIR="/etc/systemd/system"
ETC_DIR="/etc/host-env-vault"
DEFAULT_CONFIG="$ETC_DIR/config.toml"
DEFAULT_ENV="$ETC_DIR/env"
DEFAULT_BINARY="/usr/local/bin/host-env-vault"
DEFAULT_IDENTITY="$ETC_DIR/kek.age"
DEFAULT_STATE_DIR="/var/lib/host-env-vault"
DEFAULT_RUNTIME_DIR="/run/host-env-vault"
DEFAULT_ON_CALENDAR="hourly"

DRY_RUN=0
UNINSTALL=0
BINARY=""
CONFIG_PATH=""
IDENTITY=""
STATE_DIR=""
RUNTIME_DIR=""
ON_CALENDAR="$DEFAULT_ON_CALENDAR"
CATALOG_PATH=""
declare -a EXTRA_PROFILES=()
declare -a SOCKET_PROFILES=()

usage() {
  cat <<'EOF'
Usage: install-systemd.sh [options]

Install or remove host-env-vault systemd units (run as root on Linux).

Options:
  --dry-run              Print actions without writing or running systemctl
  --uninstall            Disable units, remove installed unit files, daemon-reload
  --binary PATH          host-env-vault binary (default: first on PATH, else /usr/local/bin/...)
  --config PATH          Config file (default: /etc/host-env-vault/config.toml)
  --identity PATH        Written into config when creating defaults; overrides file for catalog path
  --state-dir PATH       Same; default catalog snapshot: STATE_DIR/catalog.json
  --runtime-dir PATH     Same
  --on-calendar SPEC     Timer OnCalendar= value (default: hourly)
  --catalog PATH         catalog.json for socket profiles (default: state-dir/catalog.json)
  --profile NAME         Enable host-env-vault-serve@NAME (repeatable; merged with catalog)
  -h, --help             Show this help

Creates /etc/host-env-vault/config.toml and env with safe defaults when missing (install only).
Does not create IAM, SSM parameters, or the age identity file.
EOF
}

log() {
  printf 'install-systemd: %s\n' "$*"
}

die() {
  printf 'install-systemd: error: %s\n' "$*" >&2
  exit 1
}

run_cmd() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'dry-run:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

require_root() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    die "must run as root (or use sudo)"
  fi
}

require_linux_systemd() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    if [[ "$(uname -s)" != "Linux" ]]; then
      log "warning: not Linux; dry-run continues for CI smoke checks"
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
      log "warning: systemctl not found; dry-run will skip systemctl steps"
    fi
    return 0
  fi
  [[ "$(uname -s)" == "Linux" ]] || die "Linux with systemd is required"
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --uninstall)
        UNINSTALL=1
        shift
        ;;
      --binary)
        [[ $# -ge 2 ]] || die "--binary requires a path"
        BINARY="$2"
        shift 2
        ;;
      --config)
        [[ $# -ge 2 ]] || die "--config requires a path"
        CONFIG_PATH="$2"
        shift 2
        ;;
      --identity)
        [[ $# -ge 2 ]] || die "--identity requires a path"
        IDENTITY="$2"
        shift 2
        ;;
      --state-dir)
        [[ $# -ge 2 ]] || die "--state-dir requires a path"
        STATE_DIR="$2"
        shift 2
        ;;
      --runtime-dir)
        [[ $# -ge 2 ]] || die "--runtime-dir requires a path"
        RUNTIME_DIR="$2"
        shift 2
        ;;
      --on-calendar)
        [[ $# -ge 2 ]] || die "--on-calendar requires a value"
        ON_CALENDAR="$2"
        shift 2
        ;;
      --catalog)
        [[ $# -ge 2 ]] || die "--catalog requires a path"
        CATALOG_PATH="$2"
        shift 2
        ;;
      --profile)
        [[ $# -ge 2 ]] || die "--profile requires a name"
        EXTRA_PROFILES+=("$2")
        shift 2
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1 (try --help)"
        ;;
    esac
  done
}

resolve_binary() {
  if [[ -n "$BINARY" ]]; then
    if [[ "$DRY_RUN" -eq 0 ]]; then
      [[ -x "$BINARY" ]] || die "binary not executable: $BINARY"
    elif [[ ! -e "$BINARY" ]]; then
      die "binary not found: $BINARY"
    fi
    return 0
  fi
  if command -v host-env-vault >/dev/null 2>&1; then
    BINARY="$(command -v host-env-vault)"
    return 0
  fi
  if [[ -x "$DEFAULT_BINARY" ]]; then
    BINARY="$DEFAULT_BINARY"
    return 0
  fi
  die "host-env-vault not on PATH; pass --binary or install the binary first"
}

# Read a top-level TOML string key (identity = "..." or identity = '...').
toml_get_string() {
  local key="$1" file="$2"
  [[ -f "$file" ]] || return 1
  local line
  line="$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null | head -n 1 || true)"
  [[ -n "$line" ]] || return 1
  local value
  value="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[^=]+=[[:space:]]*//' | sed -E 's/[[:space:]]*(#.*)?$//')"
  value="${value#\"}"
  value="${value%\"}"
  value="${value#\'}"
  value="${value%\'}"
  printf '%s' "$value"
}

resolve_paths() {
  if [[ -z "$CONFIG_PATH" ]]; then
    CONFIG_PATH="$DEFAULT_CONFIG"
  fi

  local file_identity file_state file_runtime
  file_identity="$(toml_get_string identity "$CONFIG_PATH" || true)"
  file_state="$(toml_get_string state_dir "$CONFIG_PATH" || true)"
  file_runtime="$(toml_get_string runtime_dir "$CONFIG_PATH" || true)"

  IDENTITY="${IDENTITY:-${file_identity:-$DEFAULT_IDENTITY}}"
  STATE_DIR="${STATE_DIR:-${file_state:-$DEFAULT_STATE_DIR}}"
  RUNTIME_DIR="${RUNTIME_DIR:-${file_runtime:-$DEFAULT_RUNTIME_DIR}}"

  if [[ -z "$CATALOG_PATH" ]]; then
    CATALOG_PATH="$STATE_DIR/catalog.json"
  fi
}

ensure_host_layout() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    run_cmd install -d -m 0700 "$ETC_DIR"
    run_cmd install -d -m 0700 "$STATE_DIR"
    run_cmd install -d -m 0700 "$RUNTIME_DIR"
    if [[ ! -f "$DEFAULT_ENV" ]]; then
      log "would create $DEFAULT_ENV (set AWS_REGION before first sync)"
      printf 'dry-run: write %s\n' "$DEFAULT_ENV"
    fi
    if [[ ! -f "$CONFIG_PATH" ]]; then
      log "would create $CONFIG_PATH"
      printf 'dry-run: write %s\n' "$CONFIG_PATH"
    fi
    return 0
  fi

  install -d -m 0700 "$ETC_DIR"
  install -d -m 0700 "$STATE_DIR"
  install -d -m 0700 "$RUNTIME_DIR"

  if [[ ! -f "$DEFAULT_ENV" ]]; then
    cat >"$DEFAULT_ENV" <<'EOF'
# Loaded by host-env-vault systemd units. Set region before the first sync.
AWS_REGION=us-east-1
# HOST_ENV_VAULT_CONFIG=/etc/host-env-vault/config.toml
EOF
    chmod 0600 "$DEFAULT_ENV"
    log "created $DEFAULT_ENV (edit AWS_REGION)"
  fi

  if [[ ! -f "$CONFIG_PATH" ]]; then
    cat >"$CONFIG_PATH" <<EOF
identity = "$IDENTITY"
state_dir = "$STATE_DIR"
runtime_dir = "$RUNTIME_DIR"

[sync]
source = "ssm"
catalog_param = "/host-env-vault/profiles"
secrets_prefix = "/host-env-vault"
EOF
    chmod 0600 "$CONFIG_PATH"
    log "created $CONFIG_PATH"
  fi
}

substitute_unit() {
  local src="$1"
  local dest="$2"
  local tmp line
  tmp="$(mktemp)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//\/usr\/local\/bin\/host-env-vault/$BINARY}"
    if [[ "$line" == OnCalendar=* ]]; then
      line="OnCalendar=${ON_CALENDAR}"
    fi
    printf '%s\n' "$line"
  done <"$src" >"$tmp"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "would install $dest from $src"
    rm -f "$tmp"
    return 0
  fi
  install -m 0644 "$tmp" "$dest"
  rm -f "$tmp"
}

install_units() {
  [[ -d "$TEMPLATE_DIR" ]] || die "missing templates: $TEMPLATE_DIR"
  local unit
  for unit in host-env-vault-sync.service host-env-vault-sync.timer host-env-vault-serve@.service; do
    [[ -f "$TEMPLATE_DIR/$unit" ]] || die "missing template $TEMPLATE_DIR/$unit"
    substitute_unit "$TEMPLATE_DIR/$unit" "$SYSTEMD_DIR/$unit"
  done
}

systemctl_available() {
  [[ "$(uname -s)" == "Linux" ]] && command -v systemctl >/dev/null 2>&1
}

unit_is_enabled() {
  local unit="$1"
  if ! systemctl_available; then
    return 1
  fi
  if [[ "$DRY_RUN" -eq 1 ]] && [[ "$(id -u)" -ne 0 ]]; then
    return 1
  fi
  systemctl is-enabled --quiet "$unit" 2>/dev/null
}

enable_sync_timer() {
  run_cmd systemctl daemon-reload
  if unit_is_enabled host-env-vault-sync.timer; then
    log "host-env-vault-sync.timer already enabled"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      run_cmd systemctl start host-env-vault-sync.timer || true
    fi
  else
    run_cmd systemctl enable --now host-env-vault-sync.timer
  fi
}

socket_profiles_from_catalog() {
  local catalog="$1"
  [[ -f "$catalog" ]] || return 0
  if command -v jq >/dev/null 2>&1; then
    jq -r '.profiles[]? | select(.socket == true) | .name' "$catalog"
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$catalog" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
for p in data.get("profiles", []):
    if p.get("socket") is True:
        print(p["name"])
PY
    return 0
  fi
  die "need jq or python3 to read catalog.json for socket profiles"
}

profile_add() {
  local name="$1" existing
  [[ -n "$name" ]] || return 0
  for existing in "${SOCKET_PROFILES[@]}"; do
    if [[ "$existing" == "$name" ]]; then
      return 0
    fi
  done
  SOCKET_PROFILES+=("$name")
}

collect_socket_profiles() {
  SOCKET_PROFILES=()
  local name
  while IFS= read -r name; do
    profile_add "$name"
  done < <(socket_profiles_from_catalog "$CATALOG_PATH")
  for name in "${EXTRA_PROFILES[@]}"; do
    profile_add "$name"
  done
}

enable_serve_instances() {
  collect_socket_profiles
  if [[ ${#SOCKET_PROFILES[@]} -eq 0 ]]; then
    log "no socket profiles (catalog missing or empty; use --profile to enable serve@ instances)"
    return 0
  fi
  local name unit
  for name in "${SOCKET_PROFILES[@]}"; do
    unit="host-env-vault-serve@${name}.service"
    if unit_is_enabled "$unit"; then
      log "$unit already enabled"
      continue
    fi
    run_cmd systemctl enable --now "$unit"
  done
}

do_install() {
  resolve_binary
  resolve_paths
  log "binary=$BINARY config=$CONFIG_PATH state_dir=$STATE_DIR catalog=$CATALOG_PATH"
  ensure_host_layout
  install_units
  if systemctl_available; then
    enable_sync_timer
    enable_serve_instances
  elif [[ "$DRY_RUN" -eq 1 ]]; then
    run_cmd systemctl daemon-reload
    run_cmd systemctl enable --now host-env-vault-sync.timer
    collect_socket_profiles
    local name
    for name in "${SOCKET_PROFILES[@]}"; do
      run_cmd systemctl enable --now "host-env-vault-serve@${name}.service"
    done
  else
    die "systemctl required to enable units"
  fi
  log "install complete"
}

disable_serve_instances() {
  if ! systemctl_available; then
    return 0
  fi
  local unit
  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    run_cmd systemctl disable --now "$unit" || true
  done < <(systemctl list-unit-files --no-legend 'host-env-vault-serve@*.service' 2>/dev/null | awk '{print $1}' || true)
}

remove_units() {
  local unit
  for unit in host-env-vault-sync.timer host-env-vault-sync.service host-env-vault-serve@.service; do
    if [[ -f "$SYSTEMD_DIR/$unit" ]]; then
      run_cmd rm -f "$SYSTEMD_DIR/$unit"
    fi
  done
}

do_uninstall() {
  log "uninstalling host-env-vault systemd units"
  if systemctl_available; then
    run_cmd systemctl disable --now host-env-vault-sync.timer || true
    disable_serve_instances
  fi
  remove_units
  if systemctl_available; then
    run_cmd systemctl daemon-reload
  elif [[ "$DRY_RUN" -eq 1 ]]; then
    run_cmd systemctl daemon-reload
  fi
  log "uninstall complete (config under $ETC_DIR left in place)"
}

main() {
  parse_args "$@"
  require_root
  require_linux_systemd
  if [[ "$UNINSTALL" -eq 1 ]]; then
    do_uninstall
  else
    do_install
  fi
}

main "$@"
