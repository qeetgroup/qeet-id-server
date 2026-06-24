# Deployment Topology

## Overview

Qeet ID deploys as a **single Go binary** in a Docker container, with PostgreSQL (AWS RDS) as the primary datastore and Redis for rate limiting. TLS is handled by Caddy (Let's Encrypt, automatic certificate renewal).

Current production topology: **EC2 + Docker Compose + AWS RDS**.

```
Internet
   │  443 / 80
   ▼
EC2 instance
   ├── Caddy         (TLS termination, reverse proxy)  ← ports 80 + 443
   ├── qeet-id app   (Go binary, distroless container)  ← :4001, internal only
   └── Redis         (rate limiting, ephemeral)         ← :6379, internal only

AWS RDS (PostgreSQL 16)   ← accessible only from EC2 security group
```

---

## Docker Compose stack

Config: [`deploy/prod/docker-compose.yml`](../../deploy/prod/docker-compose.yml)

| Service | Image | Purpose |
|:--------|:------|:--------|
| `app` | `qeet-id:latest` | Go API server — runs migrations on startup then serves |
| `redis` | `redis:7-alpine` | Rate limiting (ephemeral — no backup needed) |
| `caddy` | `caddy:2-alpine` | TLS termination + reverse proxy |

Startup order: `redis` healthy → `app` starts (runs `migrate up` then listens) → `caddy` begins routing.

Migrations run automatically inside the app binary at startup using the embedded SQL files (`//go:embed *.sql` in `platform/database/migrations/runner.go`). They are a no-op when already up-to-date.

### Deploy / upgrade

```bash
cd /opt/qeet-id-src
git pull
docker build -f Dockerfile -t qeet-id:latest .

cd /opt/qeet-id
docker compose up -d --no-deps app   # migrations run automatically on restart
```

### Rollback

```bash
cd /opt/qeet-id-src
git checkout vX.Y.Z
docker build -f Dockerfile -t qeet-id:latest .

cd /opt/qeet-id
docker compose up -d --no-deps app
```

> ⚠️ Never roll back a migration. If a migration has a bug, write a new one to fix it forward.

---

## Images

One image. The Docker build context is the **repo root**:

```bash
docker build -f Dockerfile -t qeet-id:latest .
```

| Image | Base | Notes |
|:------|:-----|:------|
| `qeet-id` | `gcr.io/distroless/static-debian12:nonroot` | No shell, nonroot user (65532), readonly FS; migrations embedded |

Build metadata (version, commit SHA, Go version) is stamped via `-ldflags` into `platform/observability/buildinfo`.

---

## Health probes

| Probe | Endpoint | Checks |
|:------|:---------|:-------|
| Liveness | `GET /healthz` | Process alive; returns build info JSON |
| Readiness | `GET /readyz` | Alive + `pgxpool.Ping()` + Redis ping |

---

## Frontend deployment

The three frontend apps are separate build artifacts deployed independently:

| App | Build output | Recommended hosting |
|:----|:-------------|:--------------------|
| `@qeetid/admin` (console) | `apps/console/dist/` (Vite SPA) | S3 + CloudFront, or Nginx on the same EC2 |
| `@qeetid/login` (hosted login) | Next.js SSR | Vercel, or Node container |
| `@qeetid/web` (website) | Next.js SSR | Vercel, or Node container |

Frontend builds: `pnpm build` (Turborepo runs all three in parallel). Node ≥ 20.9 required (`nvm use v22.20.0`).

---

## Observability

The Go API exposes:
- `GET /metrics` — Prometheus-compatible metrics
- `GET /healthz` — liveness
- `GET /readyz` — readiness (DB + Redis)
- Structured JSON logs to stdout
- Optional OTel tracing: set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable (no-op when unset)

---

## Upgrade path

When ready to scale beyond a single server, Kubernetes (Helm) manifests, Terraform AWS modules, and a multi-environment staging setup are available in git history. See [ROADMAP.md](../../ROADMAP.md).
