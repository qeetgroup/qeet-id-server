# Deployment Runbook

## Overview

Qeet ID supports two production deployment paths:
- **Kubernetes (Helm)** — recommended for scalable production
- **Docker Compose** — for single-server deployments

Both paths run database migrations automatically before the new API server version starts.

---

## Kubernetes (Helm) deployment

### Prerequisites

- `kubectl` configured for the target cluster
- `helm` 3.x installed
- Docker image built and pushed: `ghcr.io/qeetgroup/qeet-id:<tag>`
- Secrets provisioned in AWS Secrets Manager (or equivalent) and accessible via External Secrets Operator

### Required environment variables / secrets

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string (e.g., `postgres://user:pass@host:5432/qeetid`) |
| `JWT_SIGNING_KEY` | Yes | EC P-256 private key (PEM); used to sign JWTs |
| `JWT_SECRET` | Yes | 32+ byte HMAC secret (legacy session validation) |
| `CSRF_KEY` | Yes | 32 bytes; CSRF HMAC key |
| `APP_BASE_URL` | Yes | Public base URL (e.g., `https://api.id.qeet.in`) |
| `ALLOWED_ORIGINS` | Yes | Comma-separated frontend origins (e.g., `https://admin.id.qeet.in`) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` | Yes | Email delivery |
| `SAML_SIGNING_KEY`, `SAML_SIGNING_CERT` | Yes (for SAML) | SAML IdP signing keypair |
| `REDIS_URL` | No | Redis for shared rate limiting (in-process fallback if unset) |
| `AWS_KMS_KEY_ARN` | No | AWS KMS key for secrets vault (static key used if unset) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | OTel collector endpoint (tracing disabled if unset) |

### Deploy / upgrade

```bash
helm upgrade --install qeet-id deploy/helm/qeet-id/ \
  -f deploy/helm/qeet-id/values-prod.yaml \
  --set image.tag=<git-sha> \
  --namespace qeet-id \
  --create-namespace \
  --wait
```

`--wait` blocks until all pods are Ready (including the migration Job).

### Migration behavior

A Helm pre-upgrade hook (`migration-job.yaml`) runs `golang-migrate up` before the Deployment rollout:

1. Helm pre-upgrade: migration Job starts
2. Migration Job runs `migrate -source file:///migrations -database $DATABASE_URL up`
3. Migration Job completes successfully
4. Helm Deployment rollout starts
5. New pods come up, readiness probe passes
6. Old pods drain and terminate

If the migration fails: Helm upgrade fails; the old Deployment is untouched; investigate migration errors in Job logs.

### Verify deployment

```bash
# Check pods are running
kubectl get pods -n qeet-id -l app.kubernetes.io/name=qeet-id

# Check health
kubectl exec -n qeet-id deploy/qeet-id -- curl -s http://localhost:4001/healthz | jq .
kubectl exec -n qeet-id deploy/qeet-id -- curl -s http://localhost:4001/readyz | jq .

# Check logs
kubectl logs -n qeet-id deploy/qeet-id --tail=50
```

### Rollback

```bash
# List revisions
helm history qeet-id -n qeet-id

# Roll back to previous revision
helm rollback qeet-id <revision> -n qeet-id --wait
```

Note: Rolling back the Helm chart does **not** roll back the database migration. If the new migration is incompatible with the previous code, a database rollback must be performed manually (see [database-operations.md](database-operations.md)).

---

## Docker Compose (single-server) deployment

### Setup

```bash
cd deploy/compose

# Copy and fill in env values
cp .env.prod.example .env.prod

# Start all services (runs migration on first start)
docker compose -f docker-compose.prod.yml up -d
```

Services started:
- `migrate` — runs migrations then exits
- `api` — the Go server
- `caddy` — reverse proxy (HTTPS termination, HTTP → HTTPS redirect)

### Update

```bash
# Pull new image
docker pull ghcr.io/qeetgroup/qeet-id:<new-tag>

# Update IMAGE_TAG in .env.prod, then:
docker compose -f docker-compose.prod.yml up -d

# Migration runs automatically before api restarts
```

### Verify

```bash
curl https://api.id.qeet.in/healthz
curl https://api.id.qeet.in/readyz
docker compose -f docker-compose.prod.yml logs api --tail=50
```

---

## Post-deployment checks

After any deployment, verify:

1. `GET /healthz` returns `200 OK` with build info including new `commit` hash
2. `GET /readyz` returns `200 OK` (confirms DB connectivity)
3. Login flow works end-to-end (use a test account)
4. `/metrics` endpoint is scrapeable by Prometheus
5. Check Grafana dashboard for anomalous error rates or latency spikes
