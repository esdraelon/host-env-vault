# host-env-vault

Secrets for containers, kept on the host—not in git, not in the image, and not in one shared `.env` every service can read.

The agent **syncs** from AWS SSM or from a local dev directory, **seals** encrypted bundles on disk, then either **renders** files before start or **serves** them over a unix socket while the app runs.

---

## Daily driver

This is the workflow most operators care about: install once, sync on a schedule, render before deploy, run `serve` for socket profiles.

### One-time setup

**Recommended:** run the interactive wizard on the host (needs AWS CLI v2 and operator credentials with `ssm:PutParameter`):

```bash
./scripts/setup-profile.sh
# optional install name: host-env-vault-setup
```

It ensures `host-env-vault` is on `PATH` (builds from this repo with `cargo` when needed), creates host directories, walks through AWS region/profile, catalog parameter and secrets prefix, defines your first profile, optionally uploads secret values, runs the first `sync`, and can invoke [`scripts/install-systemd.sh`](scripts/install-systemd.sh) when you are ready. Use `--non-interactive` with `HEV_SETUP_*` env vars for smoke tests ([`scripts/tests/run-setup-profile-smoke.sh`](scripts/tests/run-setup-profile-smoke.sh)).

Manual steps below are equivalent if you prefer hand-editing SSM and JSON.

1. **Build and install** the binary on the Linux host (see [Building](#building) at the bottom).

2. **Create directories** (or use your own paths and pass flags every time):

   ```bash
   sudo install -d -m 0700 /etc/host-env-vault
   sudo install -d -m 0700 /var/lib/host-env-vault
   sudo install -d -m 0700 /run/host-env-vault
   ```

3. **AWS** — On the host, use an instance role (recommended) or export credentials for manual runs. Set region in `/etc/host-env-vault/env` (loaded by the systemd units) or export it for manual CLI runs:

   ```bash
   sudo tee /etc/host-env-vault/env <<'EOF'
   AWS_REGION=us-east-1
   # Optional when not using the default path:
   # HOST_ENV_VAULT_CONFIG=/etc/host-env-vault/config.toml
   EOF
   sudo chmod 0600 /etc/host-env-vault/env
   ```

4. **Parameter Store** — Put your [profile catalog](#4-configuring-profiles) at `/host-env-vault/profiles` (or another name with `--catalog-param`). For each secret entry, create a **SecureString** at:

   ```text
   /host-env-vault/<profile>/<entry>
   ```

   Example: profile `app-web`, entry `DB_PASS` → `/host-env-vault/app-web/DB_PASS`.

5. **First sync** (creates `/etc/host-env-vault/kek.age` if missing):

   ```bash
   sudo host-env-vault sync \
     --identity /etc/host-env-vault/kek.age \
     --state-dir /var/lib/host-env-vault
   ```

6. **Socket profiles** — Start one `serve` process per profile that has `socket: true` (see [systemd units](#systemd-units) below).

### Typical day

| When | What you do |
| --- | --- |
| Secret rotated in SSM | `host-env-vault sync …` |
| New deploy | `host-env-vault render --profile app-web --dest /run/host-env-vault/app-web/current …` then restart the container |
| Runtime-only secret | App connects to `/run/host-env-vault/sockets/<profile>.sock` (no re-render) |
| AWS outage | Last good sync still works; render and serve do not call AWS |

Sync failures **do not delete** existing `.hev` bundles. Fix AWS or parameters, then sync again.

### Configuration file

Optional TOML at `/etc/host-env-vault/config.toml`, or set `HOST_ENV_VAULT_CONFIG` to another path. Pass `--config /path/to/config.toml` to override both.

**Precedence:** CLI flags beat the file; the file beats built-in defaults.

```toml
identity = "/etc/host-env-vault/kek.age"
state_dir = "/var/lib/host-env-vault"
runtime_dir = "/run/host-env-vault"

[sync]
source = "ssm"   # or "local"
catalog_param = "/host-env-vault/profiles"
secrets_prefix = "/host-env-vault"
local_secrets_dir = "/etc/host-env-vault/dev"  # when source = local
# s3_bucket = "my-recovery-bucket"
# s3_prefix = "recovery/"
```

With this in place, production sync/render/serve can omit repeated path flags:

```bash
sudo host-env-vault sync
host-env-vault render --profile app-web --dest /run/host-env-vault/app-web/current
host-env-vault serve --profile app-worker
```

### CLI cheat sheet

`sync`, `render`, and `serve` read `identity`, `state_dir`, and (for serve) `runtime_dir` from the config file when flags are omitted. `state_dir` defaults to `/var/lib/host-env-vault` if neither flag nor file sets it.

```bash
# Refresh all profiles from AWS
host-env-vault sync \
  --identity /etc/host-env-vault/kek.age \
  --state-dir /var/lib/host-env-vault

# Optional: non-default SSM names
host-env-vault sync \
  --catalog-param /my-org/vault/profiles \
  --secrets-prefix /my-org/vault/secrets \
  …

# Optional: pull plain recovery files from S3 into bundles
host-env-vault sync \
  --s3-bucket my-recovery-bucket \
  --s3-prefix recovery/ \
  …

# Write inject secrets to an empty directory (deploy step)
host-env-vault render \
  --profile app-web \
  --dest /run/host-env-vault/app-web/current \
  …

# Runtime socket (one profile per process)
host-env-vault serve \
  --profile app-worker \
  --runtime-dir /run/host-env-vault \
  …
```

`render` refuses a non-empty `--dest`. Your deploy script should use a fresh directory or remove the old slot before rendering.

### Mount into Docker

After render:

```yaml
services:
  web:
    volumes:
      - /run/host-env-vault/app-web/current:/secrets:ro
    environment:
      SECRETS_FILE: /secrets/secrets.env
```

For a runtime profile, mount only the socket:

```yaml
  worker:
    volumes:
      - /run/host-env-vault/sockets/app-worker.sock:/var/run/host-env-vault.sock
```

Map container user id to the catalog `require_uid` for that profile.

### systemd units

Maintained templates live under [`packaging/systemd/`](packaging/systemd/):

| File | Role |
| --- | --- |
| [`host-env-vault-sync.service`](packaging/systemd/host-env-vault-sync.service) | Oneshot `sync` (paths from [`config.toml`](#configuration-file); default `/etc/host-env-vault/config.toml`) |
| [`host-env-vault-sync.timer`](packaging/systemd/host-env-vault-sync.timer) | Hourly sync trigger |
| [`host-env-vault-serve@.service`](packaging/systemd/host-env-vault-serve@.service) | Template: `serve --profile %i` |

**Installer (recommended on Linux hosts):**

```bash
sudo ./scripts/install-systemd.sh
```

The installer (run as root) checks for `systemd` and `host-env-vault` on `PATH` (override with `--binary`), creates `/etc/host-env-vault/config.toml` and `env` when missing, copies [`packaging/systemd/`](packaging/systemd/) into `/etc/systemd/system/` with the detected binary path and your config paths, runs `daemon-reload`, enables `host-env-vault-sync.timer` (default `OnCalendar=hourly`; pass `--on-calendar daily`), and enables `host-env-vault-serve@<profile>.service` for each catalog profile with `socket: true` in `state_dir/catalog.json` (after at least one sync) plus any `--profile` names.

Preview without writing:

```bash
./scripts/install-systemd.sh --dry-run --binary ./target/release/host-env-vault \
  --profile app-worker
```

Remove units (leaves `/etc/host-env-vault/` config in place):

```bash
sudo ./scripts/install-systemd.sh --uninstall
```

**Manual install** — copy into `/etc/systemd/system/`, set `AWS_REGION` (and optional `HOST_ENV_VAULT_CONFIG`) in `/etc/host-env-vault/env`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now host-env-vault-sync.timer
sudo systemctl enable --now host-env-vault-serve@app-worker.service
```

Adjust the `@` instance name to each catalog profile with `socket: true`.

### Local development

**Multiple apps on one Mac:** create a gitignored [`dev-shared/`](docs/examples/dev-shared/README.md) beside the repo (starter files in [`docs/examples/dev-shared/`](docs/examples/dev-shared/)), then `./scripts/local-shared-bootstrap.sh` — see [compositional catalog](docs/compositional-catalog.md).

On a laptop you can sync without AWS. Create a directory (for example `./dev-secrets`) with:

```text
dev-secrets/
  catalog.json          # same JSON shape as the SSM catalog parameter
  app-web.env           # KEY=value lines for that profile
  app-worker.env
  files/                # optional file entries (see below)
    client.key
```

Per-profile env files are named `{profile}.env`. **Env** catalog entries must appear as `NAME=value` (same rules as rendered `secrets.env`). **File** entries are resolved in order:

1. A line `NAME=@relative/path` in `{profile}.env` (path relative to `dev-secrets/`).
2. Otherwise `dev-secrets/files/NAME` when that file exists.

```bash
host-env-vault sync \
  --source local \
  --local-secrets-dir ./dev-secrets \
  --identity ./dev/kek.age \
  --state-dir ./dev/state
```

`--source` defaults to `ssm`. Local sync does not call the AWS SDK for catalog or secrets; optional `--s3-bucket` still pulls catalog **documents** from S3 when configured. After sync, `render` and `serve` behave the same as in production (local bundles only).

---

## 1. What this is

You define **profiles** (for example `app-web`, `app-worker`). Each profile lists which secret **names** exist and whether they are **injected** at start or fetched at **runtime**.

The host keeps:

| Path | Role |
| --- | --- |
| `/etc/host-env-vault/kek.age` | Age key that encrypts local bundles (stay on this host) |
| `/var/lib/host-env-vault/` | `catalog.json` snapshot and `<profile>.hev` bundles |
| `/run/host-env-vault/` | Render output and `sockets/*.sock` |

**Sync** downloads the catalog and secrets, then seals them locally. **Render** and **serve** only read those bundles—fast and works offline after a good sync.

There is no HTTP API and no admin UI.

---

## 2. Basic profile and AWS configuration

### Credentials and IAM

The binary uses the normal AWS SDK credential chain. Production hosts should use an **instance profile** with:

- `ssm:GetParameter` (with decryption) on your catalog parameter and `{secrets_prefix}/*`
- Optional `s3:GetObject` on a recovery prefix if you use `documents` in the catalog

Set `AWS_REGION` or `AWS_DEFAULT_REGION`.

### Defaults

| Setting | Default | Flag |
| --- | --- | --- |
| Catalog parameter | `/host-env-vault/profiles` | `sync --catalog-param` |
| Secret parameters | `/host-env-vault/<profile>/<entry>` | `sync --secrets-prefix` |
| State directory | `/var/lib/host-env-vault` | `--state-dir` |

Each secret value is a Standard **SecureString** (max **4096 bytes**).

### S3 documents (optional)

Profiles may list `documents`: S3 keys for **non-secret** text (nginx snippets, plain env templates). Pass `--s3-bucket` and `--s3-prefix` on sync. Do not store private keys or API tokens in S3 through this path.

---

## 3. The two profile modes

| Mode | Catalog | Command | When the app gets data |
| --- | --- | --- | --- |
| **Inject** | `inject`, `inject_files` | `render` | At start: `secrets.env` and `files/` under `--dest` |
| **Runtime** | `runtime`, `runtime_files`, `socket: true` | `serve` | On demand via unix socket |

You can mix both on one profile: inject the database password at start, fetch a signing key over the socket when needed.

**Runtime rules**

- `socket: true` requires `require_uid` (Linux uid of the connecting process).
- Secrets unpacked in memory expire after **2000 ms** (lease); fetch and use them immediately.
- One `serve` process per socket profile.

**Inject permissions** — Optional catalog `gid` (or `render --gid`) writes `0550` / `0440` files so a container group can read without owning the directory.

---

## 4. Configuring profiles

Store catalog JSON in the catalog SSM parameter (SecureString).

```json
{
  "profiles": [
    {
      "name": "app-web",
      "inject": ["DB_PASS", "SESSION_SECRET"],
      "runtime": [],
      "inject_files": [],
      "runtime_files": [],
      "socket": false,
      "gid": 33
    },
    {
      "name": "app-worker",
      "inject": ["DB_PASS"],
      "runtime": ["API_SECRET"],
      "inject_files": [],
      "runtime_files": ["signing.pem"],
      "socket": true,
      "require_uid": 1000
    }
  ]
}
```

| Field | Purpose |
| --- | --- |
| `name` | Profile id (used in paths, bundle file, socket name) |
| `inject` / `runtime` | Env-style entry names for render vs socket |
| `inject_files` / `runtime_files` | File basenames under `files/` or socket file fetch |
| `socket` | Enable `serve` for this profile |
| `require_uid` | Required when `socket` is true |
| `gid` | Group for rendered file modes |
| `documents` | S3 keys loaded on sync (non-secret files) |

Every listed name must exist under `{secrets_prefix}/{profile}/{name}` in SSM (except document content, which comes from S3).

---

## 5. Using secrets in your app

### Injected secrets (files)

After render, read **`secrets.env`**: one `KEY=value` per line, no quoting rules beyond “value is raw bytes until newline”.

Optional **`files/<name>`** for inject file entries (PEM, keys).

#### Python

```python
from pathlib import Path

def load_injected_env(secrets_dir: Path) -> dict[str, str]:
    env_path = secrets_dir / "secrets.env"
    out: dict[str, str] = {}
    for line in env_path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        out[key] = value
    return out

# db_password = load_injected_env(Path("/secrets"))["DB_PASS"]
```

#### PHP

```php
function load_injected_env(string $secretsDir): array
{
    $lines = file($secretsDir . '/secrets.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $env = [];
    foreach ($lines as $line) {
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        [$key, $value] = explode('=', $line, 2);
        $env[$key] = $value;
    }
    return $env;
}

// $dbPass = load_injected_env('/secrets')['DB_PASS'];
```

#### TypeScript (Node)

```typescript
import fs from "node:fs";
import path from "node:path";

export function loadInjectedEnv(secretsDir: string): Record<string, string> {
  const text = fs.readFileSync(path.join(secretsDir, "secrets.env"), "utf8");
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const i = line.indexOf("=");
    if (i < 0) continue;
    out[line.slice(0, i)] = line.slice(i + 1);
  }
  return out;
}
```

### Runtime secrets (unix socket)

Socket path: `{runtime_dir}/sockets/{profile}.sock`.

**Request frame:** `opcode (1 byte)` + `length (u32 LE)` + `body (UTF-8 entry name)`  
**Opcodes:** `1` = env entry, `2` = file entry  
**Response:** `status (1 byte, 0 = ok)` + `length (u32 LE)` + `body (secret bytes)`

Complete each request within **2000 ms** of the agent unpacking the profile. Only names on the profile’s **runtime** lists are allowed.

#### Python

```python
import socket
import struct

OP_FETCH_ENV = 1
OP_FETCH_FILE = 2

def fetch_runtime_secret(sock_path: str, entry: str, *, file_entry: bool = False) -> bytes:
    opcode = OP_FETCH_FILE if file_entry else OP_FETCH_ENV
    body = entry.encode("utf-8")
    frame = bytes([opcode]) + struct.pack("<I", len(body)) + body
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        s.sendall(frame)
        header = s.recv(5)
        if len(header) != 5:
            raise RuntimeError("short response header")
        status, length = header[0], struct.unpack("<I", header[1:5])[0]
        if status != 0:
            raise PermissionError(f"denied fetching {entry!r}")
        chunks = []
        while length:
            chunk = s.recv(length)
            if not chunk:
                break
            chunks.append(chunk)
            length -= len(chunk)
        return b"".join(chunks)

# api_secret = fetch_runtime_secret("/run/host-env-vault/sockets/app-worker.sock", "API_SECRET")
```

#### PHP

```php
function fetch_runtime_secret(string $sockPath, string $entry, bool $fileEntry = false): string
{
    $opcode = $fileEntry ? 2 : 1;
    $body = $entry;
    $frame = chr($opcode) . pack('V', strlen($body)) . $body;
    $sock = socket_create(AF_UNIX, SOCK_STREAM, 0);
    socket_connect($sock, $sockPath);
    socket_write($sock, $frame, strlen($frame));
    $header = socket_read($sock, 5);
    if ($header === false || strlen($header) !== 5) {
        throw new RuntimeException('short response header');
    }
    $status = ord($header[0]);
    $length = unpack('V', substr($header, 1, 4))[1];
    if ($status !== 0) {
        throw new RuntimeException("denied fetching {$entry}");
    }
    $data = '';
    while (strlen($data) < $length) {
        $chunk = socket_read($sock, $length - strlen($data));
        if ($chunk === false || $chunk === '') {
            break;
        }
        $data .= $chunk;
    }
    socket_close($sock);
    return $data;
}
```

#### TypeScript (Node)

```typescript
import net from "node:net";

const OP_FETCH_ENV = 1;
const OP_FETCH_FILE = 2;

export function fetchRuntimeSecret(
  sockPath: string,
  entry: string,
  fileEntry = false,
): Promise<Buffer> {
  const opcode = fileEntry ? OP_FETCH_FILE : OP_FETCH_ENV;
  const body = Buffer.from(entry, "utf8");
  const frame = Buffer.concat([
    Buffer.from([opcode]),
    Buffer.alloc(4),
    body,
  ]);
  frame.writeUInt32LE(body.length, 1);

  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const client = net.createConnection(sockPath, () => client.write(frame));
    client
      .once("readable", () => {
        const header = client.read(5) as Buffer | null;
        if (!header || header.length < 5) {
          reject(new Error("short response header"));
          client.destroy();
          return;
        }
        const status = header[0];
        const length = header.readUInt32LE(1);
        if (status !== 0) {
          reject(new Error(`denied fetching ${entry}`));
          client.destroy();
          return;
        }
        let remaining = length;
        client.on("readable", () => {
          let chunk: Buffer | null;
          while (remaining > 0 && (chunk = client.read(remaining))) {
            chunks.push(chunk);
            remaining -= chunk.length;
          }
          if (remaining === 0) {
            client.destroy();
            resolve(Buffer.concat(chunks));
          }
        });
      })
      .on("error", reject);
  });
}
```

---

## Limits

| Limit | Value |
| --- | --- |
| Secrets per profile (in memory) | 32 |
| Secret size | 4096 bytes |
| Documents per profile | 20 |
| Document size | 100 KB |
| Name length | 64 characters |

Split oversized profiles in the catalog if you hit these caps.

---

## Building

```bash
cargo build --release
cargo test
```

Install `target/release/host-env-vault` to `/usr/local/bin/`.

---

## Further reading

- [docs/revision.md](docs/revision.md) — M10+ stacked work: local dev sync, config file, **systemd installer (M15)**, **profile setup wizard (M16)**
- [docs/architecture.md](docs/architecture.md) — module layout for contributors
- [docs/plan.md](docs/plan.md) — original milestone checklist
