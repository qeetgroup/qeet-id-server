# Docker Build

The image definitions live **here** (`deploy/base/docker/`), but the **build
context must be the repository root** — the build needs the whole Go module and
`platform/database/migrations/`, which live at the root. So you always build from
the root with `-f deploy/base/docker/Dockerfile`.

| File | Image | Purpose |
|---|---|---|
| `Dockerfile` | `ghcr.io/qeetgroup/qeet-id` | Distroless API server |
| `Dockerfile.migrate` | `ghcr.io/qeetgroup/qeet-id-migrate` | One-shot migration runner |
| `../../../.dockerignore` | — | At the repo root (Docker reads it only from the context root) |

## Build images locally

```bash
# API server (context = repo root)
docker build -f deploy/base/docker/Dockerfile -t qeet-id:dev .

# Migration runner
docker build -f deploy/base/docker/Dockerfile.migrate -t qeet-id-migrate:dev .
```

Or use the helper script:

```bash
./deploy/base/docker/build.sh dev        # builds both images tagged :dev
./deploy/base/docker/build.sh v1.2.3     # builds both images tagged :v1.2.3
```

## Image architecture

**API image (`Dockerfile`):**
- Stage 1: `golang:1.25-alpine` — compiles the binary with `-ldflags` stamping (version, commit, date)
- Stage 2: `gcr.io/distroless/static` — minimal runtime; no shell, no package manager
- Runs as non-root user
- Exposes port 4001

**Migration image (`Dockerfile.migrate`):**
- Based on `migrate/migrate` official image
- Copies only `platform/database/migrations/`
- Entrypoint: `migrate -source file:///migrations -database $DB_URL`

## CI/CD

Images are built and pushed by `.github/workflows/release.yml`:
1. Triggered by a `vX.Y.Z` tag (created by release-please)
2. Builds both images
3. Signs with `cosign` keyless signing (Sigstore)
4. Attaches SBOM + provenance attestations
5. Pushes to `ghcr.io/qeetgroup/qeet-id` and `ghcr.io/qeetgroup/qeet-id-migrate`

## Verify a signed image before promoting

```bash
cosign verify ghcr.io/qeetgroup/qeet-id:X.Y.Z \
  --certificate-identity-regexp 'https://github.com/qeetgroup/qeet-id/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Environment variables

All configuration is provided via environment variables at runtime. See `platform/config/config.go` for the full list. Required production variables (the server refuses to start without them outside `SERVICE_ENV=dev`):

- `DB_URL` — PostgreSQL connection string
- `JWT_SIGNING_KEY` — EC P-256 private key (PEM)
- `JWT_SECRET` — ≥32-char HMAC secret
- `APP_BASE_URL` — Public HTTPS base URL
- `ALLOWED_ORIGINS` — Comma-separated allowed CORS origins
- `CSRF_KEY` — 32-byte CSRF HMAC key

See [`../../runbooks/secrets.md`](../../runbooks/secrets.md) for secret generation commands.
