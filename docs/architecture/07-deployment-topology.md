# Deployment Topology

## Overview

Qeet ID supports two deployment paths:

| Path | When to use | Config |
|---|---|---|
| **Helm (Kubernetes)** | Production, staging | `deploy/base/helm/qeet-id/` |
| **Docker Compose** | Single-server, local dev | `deploy/environments/prod/compose/docker-compose.prod.yml` |

---

## Kubernetes (Helm)

Chart location: [`deploy/base/helm/qeet-id/`](../../deploy/base/helm/qeet-id/)

### Chart templates

| Template | Purpose |
|---|---|
| `deployment.yaml` | Go API server (single container, `go-qeet-id` image) |
| `migration-job.yaml` | Init-style Kubernetes Job that runs `golang-migrate up` before rollout |
| `service.yaml` | ClusterIP service exposing port 4001 |
| `ingress.yaml` | Ingress with TLS termination (cert-manager ready) |
| `hpa.yaml` | Horizontal Pod Autoscaler (CPU + memory metrics) |
| `pdb.yaml` | Pod Disruption Budget (min 1 replica available) |
| `serviceaccount.yaml` | Service account for workload identity |
| `configmap.yaml` | Non-secret environment variables |
| `externalsecret.yaml` | External Secrets Operator integration (fetches from AWS Secrets Manager / Vault) |
| `servicemonitor.yaml` | Prometheus `ServiceMonitor` for automatic scraping of `/metrics` |

### Deploy workflow

```bash
# Deploy / upgrade
helm upgrade --install qeet-id deploy/base/helm/qeet-id/ \
  -f deploy/environments/prod/values.yaml \
  --set image.tag=<git-sha>

# Rollback
helm rollback qeet-id <revision>

# Check status
helm status qeet-id
kubectl get pods -l app.kubernetes.io/name=qeet-id
```

The migration Job runs as a Helm hook (`pre-upgrade`, `pre-install`) — it completes before the new Deployment rollout starts.

### Required secrets

| Secret key | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_SIGNING_KEY` | EC P-256 private key (PEM or base64) |
| `JWT_SECRET` | Legacy HMAC secret (kept for session validation) |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS` | Email delivery |
| `SAML_SIGNING_KEY`, `SAML_SIGNING_CERT` | SAML IdP signing keypair |
| `CSRF_KEY` | 32-byte HMAC key for CSRF token signing |
| `AWS_KMS_KEY_ARN` | (Optional) AWS KMS key for secrets vault |

### Values files

| File | Environment |
|---|---|
| `values.yaml` | Defaults (safe for review; no secrets) |
| `environments/stage/values.yaml` | Staging overrides (reduced replicas, staging domain) |
| `environments/prod/values.yaml` | Production overrides (HPA enabled, prod domain, resource limits) |

---

## Docker Compose (production single-server)

Config: [`deploy/environments/prod/compose/docker-compose.prod.yml`](../../deploy/environments/prod/compose/docker-compose.prod.yml)

Services:
- `api` — the Go server
- `migrate` — runs migrations on startup, then exits
- `caddy` — Caddy reverse proxy (TLS termination, HTTPS redirect)
- `postgres` — (optional; typically external managed DB in prod)

Secrets are loaded from `deploy/environments/prod/compose/secrets/` via Docker secrets.

```bash
cd deploy/environments/prod/compose
docker compose -f docker-compose.prod.yml up -d
```

---

## Build and image

The Docker build context is the **repo root** (single Go module). The API image is built from the root `Dockerfile`:

```bash
docker build -t go-qeet-id:<tag> .
```

Build metadata (version, commit SHA, Go version) is stamped via `-ldflags` into `platform/observability/buildinfo` at build time and surfaced on `/healthz` and the `build_info` Prometheus metric.

The migration image is built from `Dockerfile.migrate` (copies only `migrations/`).

---

## Observability stack

Config: [`deploy/base/observability/`](../../deploy/base/observability/)

```
Go API  ──OTLP──►  OTel Collector  ──►  Prometheus / Tempo
                       │
                       └──►  Prometheus scrape ──►  Grafana

/metrics  ──────────────────────────────►  Prometheus (also scraped directly)
```

| Component | Config file |
|---|---|
| OTel Collector | `deploy/base/observability/otel-collector-config.yaml` |
| Prometheus | `deploy/base/observability/prometheus/prometheus.yml` |
| Prometheus alerts | `deploy/base/observability/prometheus/alerts.yml` |
| Grafana dashboard | `deploy/base/observability/grafana/dashboards/qeet-id.json` |

**Tracing:** Set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable; no-op (zero overhead) when unset.

**Key Prometheus metrics:**
- `http_request_duration_seconds` — per-route latency histogram
- `http_requests_in_flight` — current concurrent request count
- `build_info` — version + commit labels

---

## Health probes

| Probe | Endpoint | What it checks |
|---|---|---|
| Liveness | `GET /healthz` | Process alive; returns build info JSON |
| Readiness | `GET /readyz` | Alive + `pgxpool.Ping()` succeeds |

Kubernetes uses `/readyz` for readiness; traffic is held until the DB connection is confirmed. `/healthz` returns immediately (never fails unless the process is dead).

---

## Frontend deployment

The three frontend apps are **separate build artifacts**:

| App | Build output | Served by |
|---|---|---|
| `@qeetid/admin` (console) | `apps/console/dist/` | Static CDN or Nginx sidecar |
| `@qeetid/web` (website) | Next.js SSR | Vercel or Node.js container |
| `@qeetid/login` (hosted login) | Next.js SSR | Vercel or Node.js container |

Frontend builds: `pnpm build` (Turborepo runs all three in parallel with shared cache). Node ≥ 20.9 required (`nvm use v22.20.0`).
