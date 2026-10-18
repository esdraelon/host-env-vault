# Compositional catalog

host-env-vault treats the catalog as a **single JSON document** at sync time. Operators and CI **merge** fragments so each application can own its profile definitions without editing a monolithic file.

## Fragment format

Each file under `catalog.d/` is a JSON object:

```json
{
  "profiles": [
    {
      "name": "app-web",
      "inject": ["DB_PASS"],
      "runtime": [],
      "inject_files": [],
      "runtime_files": [],
      "socket": false
    }
  ]
}
```

Rules:

- File names sort lexically (`10-*.json`, `20-*.json`) for stable merge order.
- **Duplicate `profile.name` values fail the merge.**
- Production: run `scripts/merge-catalog.sh`, upload result to SSM (`/host-env-vault/profiles` by default).
- Local: merge copies into `dev-shared/secrets/catalog.json`, then `sync --source local`.

## Shared laptop (multi-app)

Create a **gitignored** `dev-shared/` beside the repo (see [docs/examples/dev-shared/](examples/dev-shared/README.md) for starter fragments and env templates):

1. Drop one fragment per app into `dev-shared/catalog.d/` (or copy from the examples and edit).
2. `./scripts/local-shared-bootstrap.sh` or `./scripts/local-shared-sync.sh`.
3. `render` per profile before each compose stack starts.

## Future

Native `sync --catalog-dir` may merge inside the binary; until then, `scripts/merge-catalog.sh` is the supported path.
