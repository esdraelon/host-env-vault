# host-env-vault

Spike of the host agent for Denarius and the Amtgard IDP. The implementation plan is [docs/plan.md](docs/plan.md). Source layout is [docs/architecture.md](docs/architecture.md).

It is a unix service. It has no TCP listener and no web UI.

The posture it locks in:

- A profile is a process, not a thread. PHP shares an address space, so a mode inside one process is not a boundary.
- `render` writes one profile into an empty directory. `install.sh` bind-mounts that directory read-only. Secrets are files. They are not `env_file` values, which show up in `docker inspect`.
- The on-disk bundle is ciphertext. An age identity wraps the data key. That identity is the KEK seam a cloud KMS provider can replace without renaming profiles.
- `serve` keeps the data key only for `denarius-worker`. It drops the sealed env and files after checking the bundle. The socket path is the profile. Frames wrap or unwrap a 32-byte key. A frame cannot name another profile or ask for `STRIPE_SECRET_KEY`.
- Web, connect, and both IDP profiles have no socket.

## Profiles

| Profile | Runtime socket | Holds | Does not hold |
| --- | --- | --- | --- |
| `denarius-web` | no | `DB_PASS`, `IDP_CLIENT_SECRET`, `STRIPE_PUBLISHABLE_KEY` | Stripe secret, `APP_KEY` |
| `denarius-worker` | yes | restricted Stripe key, webhook and provider secrets, `APP_KEY`, Teller key files | publishable key |
| `denarius-connect` | no | `STRIPE_SECRET_KEY` only | database, `APP_KEY` |
| `idp-http` | no | provisional HTTP secrets, including the signing key file | |
| `idp-worker` | no | provisional `DB_PASS`, `JWT_KEY`, signing key file | mail and social client secrets |

`idp-http` and `idp-worker` are marked provisional. Both may still open `oauth-private.key` until those processes are traced. Seal already refuses anything outside the list, so a wrong name fails closed.

## Layout

```
/etc/host-env-vault/kek.age                         age identity, mode 0400, not in bundle backups
/var/lib/host-env-vault/denarius-worker.hev         ciphertext bundle
/run/host-env-vault/denarius/blue/worker/           tmpfs render: secrets.env and files/
/run/host-env-vault/sockets/denarius-worker.sock    mode 0600, mounted only into the worker
```

Rendered with no gid: directory `0700`, files `0400`. That matches the current images, which run as root.

Rendered with `--gid 33`: directory `0550` root:33, files `0440` root:33. Use that when the container user is `www-data` and does not own the directory. Pair it with `serve --require-uid` set to the host uid of the connecting process. The missing mount is the real authorization. The uid check is the second one.

## Bundle

`HEV1`, version, profile name, age-wrapped 32-byte DEK, XChaCha20-Poly1305 of the entries. The profile name is associated data. A relabeled header does not decrypt. A fresh DEK is used for every seal.

## Commands

```
cargo test

cargo run -- keygen --out /etc/host-env-vault/kek.age

cargo run -- seal \
  --profile denarius-worker \
  --identity /etc/host-env-vault/kek.age \
  --in ./staging/denarius-worker \
  --out /var/lib/host-env-vault/denarius-worker.hev

cargo run -- render \
  --profile denarius-worker \
  --identity /etc/host-env-vault/kek.age \
  --bundle /var/lib/host-env-vault/denarius-worker.hev \
  --dest /run/host-env-vault/denarius/blue/worker
```

Staging directory:

```
staging/denarius-worker/secrets.env
staging/denarius-worker/files/teller.pem
staging/denarius-worker/files/teller.key
```

`install.sh` calls `render` before `docker compose up`. Plain settings stay in the ordinary env file. `TELLER_CERT_PATH` in that file points at the mounted `files/teller.pem`.

```
cargo run -- serve \
  --identity /etc/host-env-vault/kek.age \
  --state-dir /var/lib/host-env-vault \
  --runtime-dir /run/host-env-vault \
  --poll-secs 3600
```

The poll re-reads runtime bundles and replaces the data key. It does not decrypt `denarius-web` or the IDP profiles into the daemon.

`packaging/host-env-vault.service` is the systemd unit. It starts before Docker.

## Left for the next cut

- A KMS implementation of the same wrap/unwrap the age identity does now.
- `install.sh` and compose mounts in Denarius and the IDP.
- A trace of which files `amtgardidpapp` and `jwt-pvh-worker.php` open, then a tighter IDP allowlist.
- `USER www-data` in the images, with `--gid` and `--require-uid` to match.
