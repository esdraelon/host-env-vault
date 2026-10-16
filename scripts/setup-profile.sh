#!/usr/bin/env bash
# Interactive profile setup wizard (M16): binary, AWS, catalog, secrets, first sync.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ETC_DIR="/etc/host-env-vault"
DEFAULT_CONFIG="$ETC_DIR/config.toml"
DEFAULT_ENV="$ETC_DIR/env"
DEFAULT_BINARY="/usr/local/bin/host-env-vault"
DEFAULT_IDENTITY="$ETC_DIR/kek.age"
DEFAULT_STATE_DIR="/var/lib/host-env-vault"
DEFAULT_RUNTIME_DIR="/run/host-env-vault"
DEFAULT_CATALOG_PARAM="/host-env-vault/profiles"
DEFAULT_SECRETS_PREFIX="/host-env-vault"

NON_INTERACTIVE=0
DRY_RUN=0
SKIP_SYNC=0
SKIP_LAYOUT=0
BINARY=""
IDENTITY="$DEFAULT_IDENTITY"
STATE_DIR="$DEFAULT_STATE_DIR"
RUNTIME_DIR="$DEFAULT_RUNTIME_DIR"
CONFIG_PATH="$DEFAULT_CONFIG"
AWS_REGION="${HEV_SETUP_AWS_REGION:-${AWS_REGION:-${AWS_DEFAULT_REGION:-}}}"
AWS_PROFILE="${HEV_SETUP_AWS_PROFILE:-${AWS_PROFILE:-}}"
CATALOG_PARAM="${HEV_SETUP_CATALOG_PARAM:-$DEFAULT_CATALOG_PARAM}"
SECRETS_PREFIX="${HEV_SETUP_SECRETS_PREFIX:-$DEFAULT_SECRETS_PREFIX}"
PROFILE_NAME="${HEV_SETUP_PROFILE_NAME:-}"
DELIVERY="${HEV_SETUP_DELIVERY:-}"
INJECT_ENV="${HEV_SETUP_INJECT_ENV:-}"
RUNTIME_ENV="${HEV_SETUP_RUNTIME_ENV:-}"
INJECT_FILES="${HEV_SETUP_INJECT_FILES:-}"
RUNTIME_FILES="${HEV_SETUP_RUNTIME_FILES:-}"
REQUIRE_UID="${HEV_SETUP_REQUIRE_UID:-}"
GID="${HEV_SETUP_GID:-}"
SECRET_VALUES_FILE="${HEV_SETUP_SECRET_VALUES:-}"
PROFILE_JSON=""

usage() {
  cat <<'EOF'
Usage: setup-profile.sh [options]

Walk through host layout, AWS, a new catalog profile, optional SSM secret values,
and the first sync. Requires AWS CLI v2 and credentials with ssm:PutParameter for
the wizard (host role needs ssm:GetParameter only).

Options:
  --non-interactive   Use HEV_SETUP_* / AWS_* env vars (see below); no prompts
  --dry-run           Print actions; skip SSM writes and sync
  --skip-sync         Stop after SSM/catalog (also HEV_SETUP_SKIP_SYNC=1)
  --skip-layout       Do not create /etc or /var directories
  -h, --help          Show this help

Non-interactive env (required with --non-interactive unless defaults suffice):
  HEV_SETUP_AWS_REGION, HEV_SETUP_AWS_PROFILE
  HEV_SETUP_CATALOG_PARAM, HEV_SETUP_SECRETS_PREFIX
  HEV_SETUP_PROFILE_NAME, HEV_SETUP_DELIVERY (inject|runtime|both)
  HEV_SETUP_INJECT_ENV, HEV_SETUP_RUNTIME_ENV (comma-separated)
  HEV_SETUP_INJECT_FILES, HEV_SETUP_RUNTIME_FILES
  HEV_SETUP_REQUIRE_UID, HEV_SETUP_GID
  HEV_SETUP_SECRET_VALUES   JSON object: {"ENTRY":"value",...}
  HEV_SETUP_SKIP_SYNC=1, HEV_SETUP_BINARY=/path/to/host-env-vault

Install name: host-env-vault-setup (optional symlink to this script).
EOF
}

log() {
  printf 'setup-profile: %s\n' "$*"
}

die() {
  printf 'setup-profile: error: %s\n' "$*" >&2
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

maybe_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --non-interactive)
        NON_INTERACTIVE=1
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --skip-sync)
        SKIP_SYNC=1
        shift
        ;;
      --skip-layout)
        SKIP_LAYOUT=1
        shift
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
  [[ "${HEV_SETUP_SKIP_SYNC:-}" != "1" ]] || SKIP_SYNC=1
  [[ "${HEV_SETUP_SKIP_LAYOUT:-}" != "1" ]] || SKIP_LAYOUT=1
  [[ -n "${HEV_SETUP_BINARY:-}" ]] && BINARY="$HEV_SETUP_BINARY"
}

valid_profile_name() {
  local name="$1"
  [[ -n "$name" && ${#name} -le 64 ]] || return 1
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
}

valid_entry_name() {
  valid_profile_name "$1"
}

split_csv() {
  local csv="$1"
  local part
  if [[ -z "$csv" ]]; then
    return 0
  fi
  IFS=',' read -r -a _SPLIT_PARTS <<<"$csv"
  for part in "${_SPLIT_PARTS[@]}"; do
    part="${part#"${part%%[![:space:]]*}"}"
    part="${part%"${part##*[![:space:]]}"}"
    [[ -n "$part" ]] && printf '%s\n' "$part"
  done
}

prompt() {
  local msg="$1" default="${2:-}" reply
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    printf '%s' "${default}"
    return 0
  fi
  if [[ -n "$default" ]]; then
    read -r -p "$msg [$default]: " reply
    printf '%s' "${reply:-$default}"
  else
    read -r -p "$msg: " reply
    printf '%s' "$reply"
  fi
}

prompt_yes_no() {
  local msg="$1" default="${2:-y}" reply normalized
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    [[ "$default" =~ ^[Yy] ]]
    return
  fi
  read -r -p "$msg [y/N]: " reply
  reply="${reply:-$default}"
  normalized="$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]')"
  [[ "$normalized" == "y" || "$normalized" == "yes" ]]
}

prompt_hidden() {
  local msg="$1" reply
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    printf ''
    return 0
  fi
  read -r -s -p "$msg: " reply
  printf '\n' >&2
  printf '%s' "$reply"
}

read_env_list() {
  local label="$1" preset="${2:-}" line
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    split_csv "$preset"
    return 0
  fi
  log "$label (comma-separated, empty line when done)"
  while true; do
    read -r -p "  name: " line
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && break
    if ! valid_entry_name "$line"; then
      log "invalid name (use alphanumeric, _, ., -; max 64)"
      continue
    fi
    printf '%s\n' "$line"
  done
}

ensure_aws_cli() {
  command -v aws >/dev/null 2>&1 || die "AWS CLI v2 is required (install awscli v2)"
  if aws --version 2>&1 | grep -q 'aws-cli/1'; then
    die "AWS CLI v1 detected; install AWS CLI v2"
  fi
}

export_aws_env() {
  if [[ -n "$AWS_REGION" ]]; then
    export AWS_REGION AWS_DEFAULT_REGION="$AWS_REGION"
  fi
  if [[ -n "$AWS_PROFILE" ]]; then
    export AWS_PROFILE
  fi
}

aws_cmd() {
  export_aws_env
  aws "$@"
}

verify_aws_identity() {
  log "verifying AWS credentials (sts get-caller-identity)"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "dry-run: skip sts get-caller-identity"
    return 0
  fi
  aws_cmd sts get-caller-identity >/dev/null
}

show_iam_snippets() {
  cat <<EOF

IAM hints (adjust ARNs and KMS as needed):

  Host / sync role (GetParameter only):
    {
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:GetParameters"],
      "Resource": [
        "arn:aws:ssm:*:*:parameter${CATALOG_PARAM}",
        "arn:aws:ssm:*:*:parameter${SECRETS_PREFIX}/*"
      ]
    }

  Operator / wizard role (PutParameter for setup only):
    {
      "Effect": "Allow",
      "Action": ["ssm:PutParameter", "ssm:GetParameter"],
      "Resource": [
        "arn:aws:ssm:*:*:parameter${CATALOG_PARAM}",
        "arn:aws:ssm:*:*:parameter${SECRETS_PREFIX}/*"
      ]
    }

EOF
}

install_binary_from_source() {
  local dest="$1"
  log "building host-env-vault from $REPO_ROOT"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "dry-run: would run cargo build --release in $REPO_ROOT"
    BINARY="$dest"
    return 0
  fi
  [[ -f "$REPO_ROOT/Cargo.toml" ]] || die "no Cargo.toml at repo root"
  command -v cargo >/dev/null 2>&1 || die "cargo not found; install Rust or put host-env-vault on PATH"
  (cd "$REPO_ROOT" && cargo build --release)
  maybe_sudo install -m 0755 "$REPO_ROOT/target/release/host-env-vault" "$dest"
  BINARY="$dest"
}

ensure_binary() {
  if [[ -n "$BINARY" ]]; then
    [[ "$DRY_RUN" -eq 1 || -x "$BINARY" ]] || die "binary not executable: $BINARY"
    return 0
  fi
  if command -v host-env-vault >/dev/null 2>&1; then
    BINARY="$(command -v host-env-vault)"
    log "using host-env-vault on PATH: $BINARY"
    return 0
  fi
  if [[ -x "$DEFAULT_BINARY" ]]; then
    BINARY="$DEFAULT_BINARY"
    return 0
  fi
  if [[ -f "$REPO_ROOT/Cargo.toml" ]] && command -v cargo >/dev/null 2>&1; then
    local dest="$DEFAULT_BINARY"
    if [[ "$(id -u)" -ne 0 ]]; then
      if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
        dest="${HEV_SETUP_INSTALL_DIR:-$HOME/.local/bin}/host-env-vault"
      elif prompt_yes_no "Install to ~/.local/bin instead of /usr/local/bin?" "y"; then
        dest="$HOME/.local/bin/host-env-vault"
        mkdir -p "$HOME/.local/bin"
      fi
    fi
    install_binary_from_source "$dest"
    return 0
  fi
  cat >&2 <<'EOF'
setup-profile: host-env-vault not found.

Install options:
  - Put a release binary on PATH
  - Clone this repo and re-run (cargo build --release)
  - When published: download the release tarball from the project releases page

EOF
  exit 1
}

write_config_toml() {
  local path="$1"
  if [[ -f "$path" ]]; then
    return 0
  fi
  log "creating $path"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'dry-run: write %s\n' "$path"
    return 0
  fi
  maybe_sudo tee "$path" >/dev/null <<EOF
identity = "$IDENTITY"
state_dir = "$STATE_DIR"
runtime_dir = "$RUNTIME_DIR"

[sync]
source = "ssm"
catalog_param = "$CATALOG_PARAM"
secrets_prefix = "$SECRETS_PREFIX"
EOF
  maybe_sudo chmod 0600 "$path"
}

write_env_file() {
  local path="$DEFAULT_ENV"
  if [[ -f "$path" || -z "$AWS_REGION" ]]; then
    return 0
  fi
  log "creating $path with AWS_REGION"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'dry-run: write %s\n' "$path"
    return 0
  fi
  maybe_sudo tee "$path" >/dev/null <<EOF
AWS_REGION=$AWS_REGION
# HOST_ENV_VAULT_CONFIG=$CONFIG_PATH
EOF
  maybe_sudo chmod 0600 "$path"
}

ensure_host_layout() {
  if [[ "$SKIP_LAYOUT" -eq 1 ]]; then
    log "skipping host directory layout (--skip-layout)"
    return 0
  fi
  log "ensuring host directories (sudo when needed)"
  run_cmd maybe_sudo install -d -m 0700 "$ETC_DIR"
  run_cmd maybe_sudo install -d -m 0700 "$STATE_DIR"
  run_cmd maybe_sudo install -d -m 0700 "$RUNTIME_DIR"
  write_env_file
  write_config_toml "$CONFIG_PATH"
}

phase_aws() {
  ensure_aws_cli
  if [[ -z "$AWS_REGION" ]]; then
    AWS_REGION="$(prompt "AWS region (AWS_REGION)" "us-east-1")"
  fi
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    AWS_PROFILE="$(prompt "AWS profile (optional, empty for default chain)" "${AWS_PROFILE}")"
  fi
  export_aws_env
  verify_aws_identity
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    CATALOG_PARAM="$(prompt "Catalog SSM parameter name" "$CATALOG_PARAM")"
    SECRETS_PREFIX="$(prompt "Secrets SSM prefix" "$SECRETS_PREFIX")"
    show_iam_snippets
  else
    log "catalog_param=$CATALOG_PARAM secrets_prefix=$SECRETS_PREFIX"
  fi
}

collect_profile_fields() {
  if [[ -z "$PROFILE_NAME" ]]; then
    while true; do
      PROFILE_NAME="$(prompt "Profile name (e.g. app-web)" "")"
      if valid_profile_name "$PROFILE_NAME"; then
        break
      fi
      log "invalid profile name"
    done
  else
    valid_profile_name "$PROFILE_NAME" || die "invalid HEV_SETUP_PROFILE_NAME: $PROFILE_NAME"
  fi

  if [[ -z "$DELIVERY" ]]; then
    while true; do
      DELIVERY="$(prompt "Delivery: inject | runtime | both" "both")"
      DELIVERY="$(printf '%s' "$DELIVERY" | tr '[:upper:]' '[:lower:]')"
      case "$DELIVERY" in
        inject | runtime | both) break ;;
        *) log "choose inject, runtime, or both" ;;
      esac
    done
  fi
  DELIVERY="$(printf '%s' "$DELIVERY" | tr '[:upper:]' '[:lower:]')"

  local -a inject_arr=() runtime_arr=() inject_files_arr=() runtime_files_arr=()
  if [[ "$DELIVERY" == "inject" || "$DELIVERY" == "both" ]]; then
    while IFS= read -r line; do inject_arr+=("$line"); done < <(read_env_list "Inject env names" "$INJECT_ENV")
    while IFS= read -r line; do inject_files_arr+=("$line"); done < <(read_env_list "Inject file basenames" "$INJECT_FILES")
  fi
  if [[ "$DELIVERY" == "runtime" || "$DELIVERY" == "both" ]]; then
    while IFS= read -r line; do runtime_arr+=("$line"); done < <(read_env_list "Runtime env names" "$RUNTIME_ENV")
    while IFS= read -r line; do runtime_files_arr+=("$line"); done < <(read_env_list "Runtime file basenames" "$RUNTIME_FILES")
  fi

  local socket=false
  if [[ "$DELIVERY" == "runtime" || "$DELIVERY" == "both" ]] && [[ ${#runtime_arr[@]} -gt 0 || ${#runtime_files_arr[@]} -gt 0 ]]; then
    socket=true
  fi

  if [[ "$socket" == true && -z "$REQUIRE_UID" ]]; then
    REQUIRE_UID="$(prompt "require_uid (container UID for socket access)" "1000")"
  fi
  if [[ -z "$GID" && "$NON_INTERACTIVE" -eq 0 ]]; then
    local gid_input
    gid_input="$(prompt "Optional gid for render permissions (empty to skip)" "")"
    [[ -n "$gid_input" ]] && GID="$gid_input"
  fi

  PROFILE_JSON="$(
    python3 - "$PROFILE_NAME" "$socket" "$REQUIRE_UID" "$GID" "${inject_arr[*]}" "${runtime_arr[*]}" \
      "${inject_files_arr[*]}" "${runtime_files_arr[*]}" <<'PY'
import json, sys
name, socket_s, require_uid_s, gid_s = sys.argv[1:5]
rest = sys.argv[5:]
def words(s):
    return [w for w in s.split() if w]
inject, runtime, inject_files, runtime_files = [words(x) for x in rest]
profile = {
    "name": name,
    "inject": inject,
    "runtime": runtime,
    "inject_files": inject_files,
    "runtime_files": runtime_files,
    "socket": socket_s == "true",
}
if require_uid_s:
    profile["require_uid"] = int(require_uid_s)
if gid_s:
    profile["gid"] = int(gid_s)
print(json.dumps(profile, separators=(",", ":")))
PY
  )"
}

ssm_get_catalog_text() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf ''
    return 0
  fi
  if aws_cmd ssm get-parameter --name "$CATALOG_PARAM" --with-decryption --query Parameter.Value --output text 2>/dev/null; then
    return 0
  fi
  printf ''
}

merge_catalog_and_put() {
  local existing new_catalog
  existing="$(ssm_get_catalog_text)"
  if [[ -z "$existing" ]]; then
    new_catalog="$(python3 - "$PROFILE_JSON" <<'PY'
import json, sys
print(json.dumps({"profiles": [json.loads(sys.argv[1])]}, indent=2))
PY
    )"
  else
    if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
      if python3 - "$existing" "$PROFILE_NAME" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
for p in data.get("profiles", []):
    if p.get("name") == sys.argv[2]:
        sys.exit(0)
sys.exit(1)
PY
      then
        prompt_yes_no "Profile '$PROFILE_NAME' exists in catalog; replace it?" "n" || die "aborted"
      fi
    fi
    new_catalog="$(python3 - "$existing" "$PROFILE_JSON" "$PROFILE_NAME" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
new_p = json.loads(sys.argv[2])
name = sys.argv[3]
profiles = [p for p in data.get("profiles", []) if p.get("name") != name]
profiles.append(new_p)
print(json.dumps({"profiles": profiles}, indent=2))
PY
    )"
  fi
  log "uploading catalog to $CATALOG_PARAM"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'dry-run: catalog JSON (%s bytes)\n' "${#new_catalog}"
    return 0
  fi
  aws_cmd ssm put-parameter \
    --name "$CATALOG_PARAM" \
    --value "$new_catalog" \
    --type SecureString \
    --overwrite >/dev/null
}

collect_entry_names() {
  python3 - "$PROFILE_JSON" <<'PY'
import json, sys
p = json.loads(sys.argv[1])
names = set()
for key in ("inject", "runtime", "inject_files", "runtime_files"):
    names.update(p.get(key) or [])
for n in sorted(names):
    print(n)
PY
}

secret_value_for_entry() {
  local entry="$1"
  if [[ -n "$SECRET_VALUES_FILE" && -f "$SECRET_VALUES_FILE" ]]; then
    python3 - "$SECRET_VALUES_FILE" "$entry" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
print(data.get(sys.argv[2], ""))
PY
    return 0
  fi
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    printf ''
    return 0
  fi
  local val
  if prompt_yes_no "Set SSM value for entry '$entry' now?" "y"; then
    val="$(prompt_hidden "  Value")"
    printf '%s' "$val"
  else
    printf ''
  fi
}

phase_secret_values() {
  local entry param value
  log "optional secret values (skipped entries must exist in SSM before sync succeeds)"
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    value="$(secret_value_for_entry "$entry")"
    [[ -n "$value" ]] || continue
    param="${SECRETS_PREFIX}/${PROFILE_NAME}/${entry}"
    log "put-parameter $param"
    if [[ "$DRY_RUN" -eq 1 ]]; then
      run_cmd aws_cmd ssm put-parameter \
        --name "$param" \
        --value "$value" \
        --type SecureString \
        --overwrite
    else
      aws_cmd ssm put-parameter \
        --name "$param" \
        --value "$value" \
        --type SecureString \
        --overwrite >/dev/null
    fi
  done < <(collect_entry_names)
}

run_first_sync() {
  if [[ "$SKIP_SYNC" -eq 1 ]]; then
    log "skipping sync (--skip-sync)"
    return 0
  fi
  log "running first sync"
  local -a sync_args=(
    "$BINARY" sync
    --identity "$IDENTITY"
    --state-dir "$STATE_DIR"
    --catalog-param "$CATALOG_PARAM"
    --secrets-prefix "$SECRETS_PREFIX"
  )
  if [[ -f "$CONFIG_PATH" ]]; then
    sync_args+=(--config "$CONFIG_PATH")
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'dry-run:'
    printf ' %q' maybe_sudo "${sync_args[@]}"
    printf '\n'
  else
    maybe_sudo "${sync_args[@]}"
  fi
}

print_next_steps() {
  local bundle="$STATE_DIR/${PROFILE_NAME}.hev"
  cat <<EOF

Setup complete for profile '$PROFILE_NAME'.

  Bundle (after sync): $bundle
  Catalog snapshot:    $STATE_DIR/catalog.json

EOF
  case "$DELIVERY" in
    inject)
      cat <<EOF
  Inject deploy example:
    host-env-vault render --profile $PROFILE_NAME \\
      --dest $RUNTIME_DIR/$PROFILE_NAME/current \\
      --identity $IDENTITY --state-dir $STATE_DIR

  Mount rendered secrets.env or files/ into your compose service.

EOF
      ;;
    runtime | both)
      cat <<EOF
  Runtime socket: $RUNTIME_DIR/sockets/${PROFILE_NAME}.sock
  Enable systemd serve instance (after M15 installer):
    sudo systemctl enable --now host-env-vault-serve@${PROFILE_NAME}.service

EOF
      ;;
  esac
}

offer_systemd_installer() {
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    return 0
  fi
  if ! prompt_yes_no "Run scripts/install-systemd.sh now (Linux root)?" "n"; then
    return 0
  fi
  if [[ "$(uname -s)" != "Linux" ]]; then
    log "not on Linux; run install-systemd.sh on the host"
    return 0
  fi
  maybe_sudo "$REPO_ROOT/scripts/install-systemd.sh" --profile "$PROFILE_NAME"
}

main() {
  parse_args "$@"
  command -v python3 >/dev/null 2>&1 || die "python3 is required for catalog JSON"
  ensure_binary
  ensure_host_layout
  phase_aws
  collect_profile_fields
  merge_catalog_and_put
  phase_secret_values
  run_first_sync
  print_next_steps
  offer_systemd_installer
}

main "$@"
