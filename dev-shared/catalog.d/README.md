# Catalog fragments

Add one JSON file per application stack. Files merge in lexicographic order (`10-*.json`, `20-*.json`, …).

Each fragment must use **neutral profile names** (`app-web`, `api-http`, …). Do not commit product- or org-specific catalog files here; keep those in the owning application repo and copy or symlink fragments locally if needed.

See [docs/compositional-catalog.md](../../docs/compositional-catalog.md).
