# Deployment Runbook

Full step-by-step deployment guide: **[deploy/prod/deploy.md](../../deploy/prod/deploy.md)**

This file is a quick-reference summary; the authoritative guide with RDS setup, security group config, and first-deploy walkthrough is in `deploy/prod/deploy.md`.

---

## Stack

EC2 (Docker Compose) + AWS RDS (PostgreSQL 16) + Redis (local container) + Caddy (TLS).

Migrations run automatically on startup — no separate step needed.

```bash
# Deploy / upgrade (on EC2)
cd /opt/qeet-id-src && git pull
docker build -f Dockerfile -t qeet-id:latest .

cd /opt/qeet-id
docker compose up -d --no-deps app   # migrations run automatically

# Verify
curl https://api.id.qeet.in/healthz     # → {"status":"ok"}
curl https://api.id.qeet.in/readyz      # → {"status":"ok","db":"ok","redis":"ok"}
```

---

## Rollback

```bash
cd /opt/qeet-id-src
git checkout vX.Y.Z
docker build -f Dockerfile -t qeet-id:latest .

cd /opt/qeet-id
docker compose up -d --no-deps app
docker compose logs -f app           # confirm clean startup
```

---

## Post-deployment checks

1. `curl https://api.id.qeet.in/healthz` returns `200 OK`
2. `curl https://api.id.qeet.in/readyz` returns `200 OK` (confirms DB + Redis)
3. `docker compose logs app --tail=20` — no `ERROR` lines at startup
4. Login flow works end-to-end (use a test account)
5. Check `GET /metrics` is reachable from your monitoring agent

---

## Useful commands

```bash
docker compose ps                    # container statuses
docker compose logs -f app           # tail app logs
docker compose logs -f caddy         # tail caddy/TLS logs
docker compose restart app           # restart without image change
```
