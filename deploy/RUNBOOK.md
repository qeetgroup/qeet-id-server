# Qeet ID — Deployment & DR Runbook

What's in `deploy/`:

| Path | Purpose |
| --- | --- |
| `helm/qeet-id/` | Helm chart (API Deployment, Service, HPA, PDB, Ingress, ConfigMap/Secret, **pre‑upgrade migration Job hook**). |
| `Dockerfile.migrate` | golang‑migrate CLI with our migrations baked in. |
| `docker-compose.prod.yml` | Single‑host deploy (managed Postgres/Redis), no Kubernetes. |
| `../backend/Dockerfile` | The API image (distroless, nonroot, static). |

Target: AWS (EKS + RDS Postgres + ElastiCache). The chart is cloud‑agnostic.

---

## 1. Build & push images

```bash
TAG=$(git -C backend rev-parse --short HEAD)   # or a semver tag
# API
docker build -t ghcr.io/qeetgroup/qeet-id:$TAG backend
# Migrations (build from repo root so backend/migrations resolves)
docker build -f deploy/Dockerfile.migrate -t ghcr.io/qeetgroup/qeet-id-migrate:$TAG .
docker push ghcr.io/qeetgroup/qeet-id:$TAG
docker push ghcr.io/qeetgroup/qeet-id-migrate:$TAG
```

## 2. Prod env gate (must be satisfied or the app refuses to boot)

`SERVICE_ENV=prod` activates `config.Validate()`. It **refuses to start** unless:

- `JWT_SECRET` is set, ≥32 chars, not a placeholder
- `JWT_SIGNING_KEY` is set (PEM EC P‑256 private key — `openssl ecparam -name prime256v1 -genkey -noout`)
- `SECRETS_KEY` is set (base64 32‑byte AES key — `openssl rand -base64 32`)
- `ALLOWED_ORIGINS` is an explicit list (no `*`)
- `APP_BASE_URL` is a real origin (not localhost)
- `CSRF_DISABLED` / `AUTH_DEV_TRUST_HEADERS` are **unset**

Also set for the hosted login + cross‑subdomain CSRF: `LOGIN_BASE_URL`, `CSRF_COOKIE_DOMAIN` (e.g. `.acme.com`), `WEBAUTHN_RP_ID`. For email/SMS: `SMTP_*`, `TWILIO_*`. For shared rate limits: `REDIS_URL`.

## 3. Secrets

**Do not commit secret values.** Use one of:

- **External Secrets Operator** (pulls from AWS Secrets Manager) → set `secrets.existingSecret=qeet-id-secrets`, `secrets.create=false`.
- **Sealed Secrets / SOPS** committed encrypted.

The chart can also create a Secret from `secrets.data.*` for non‑prod only.

## 4. Deploy (Helm)

```bash
helm upgrade --install qeet-id deploy/helm/qeet-id \
  --namespace qeet-id --create-namespace \
  --set image.tag=$TAG --set migrate.image.tag=$TAG \
  --set secrets.existingSecret=qeet-id-secrets \
  --set config.APP_BASE_URL=https://app.acme.com \
  --set config.ALLOWED_ORIGINS=https://app.acme.com\,https://admin.acme.com \
  --set ingress.enabled=true --set ingress.className=alb

kubectl -n qeet-id rollout status deploy/qeet-id
```

The `helm.sh/hook: pre-upgrade` migration Job runs **to completion before** the
Deployment rolls. The rollout is `maxUnavailable: 0` and gated on `/readyz`, so
there's no downtime.

## 5. Zero‑downtime migrations (expand / contract)

Because migrations run *before* the new pods (and old pods are still serving
during the rollout), **every migration must be backward‑compatible with the
currently‑running version**. Follow expand/contract:

- **Expand** (safe, deploy anytime): add nullable columns, add tables, add
  indexes `CONCURRENTLY`, add new enum values, backfill in batches.
- **Contract** (only after all code using the old shape is gone): drop columns,
  rename (do as add‑new + backfill + switch + drop‑old across *two* releases),
  add `NOT NULL`/constraints (add as `NOT VALID` then `VALIDATE` separately).
- **Never** rewrite a large table or take `ACCESS EXCLUSIVE` locks in a single
  step during business hours.
- Repo rule (already enforced): never edit an applied migration — add a new
  pair. `down` migrations are for local/dev only; **don't down‑migrate prod** —
  fix forward.

Signing‑key rotation is online too: set the new `JWT_SIGNING_KEY` and put the
previous **public** key in `JWT_RETIRED_KEYS` so in‑flight tokens keep verifying
until they expire, then drop it after one access‑token TTL.

## 6. Backups & PITR

- **RDS (recommended):** enable automated backups (retention ≥ 7 days) and
  ensure PITR is on (it is, with automated backups). Take a **manual snapshot
  before each deploy** that includes a contract migration.
  ```bash
  aws rds create-db-snapshot --db-instance-identifier qeet-id \
    --db-snapshot-identifier qeet-id-predeploy-$TAG
  ```
- **Self‑managed Postgres:** nightly `pg_dump` + continuous WAL archiving
  (e.g. WAL‑G to S3) for PITR.
- **Verify, don't assume:** monthly, restore the latest backup into a scratch DB
  and run `make migrate-up` + a smoke query (see §7). An unverified backup is
  not a backup.

## 7. Disaster recovery / restore drill

Target **RPO ≤ 5 min** (PITR/WAL) and **RTO ≤ 30 min**.

1. Restore: RDS point‑in‑time restore to a new instance (or `pg_restore` from
   the latest dump) — `aws rds restore-db-instance-to-point-in-time …`.
2. Point the app at it: update `DB_URL` in the secret; `helm upgrade` (the
   migration Job will no‑op if already current).
3. Smoke test:
   ```bash
   kubectl -n qeet-id run -it --rm curl --image=curlimages/curl --restart=Never -- \
     curl -s http://qeet-id/readyz
   curl -s https://api.acme.com/.well-known/jwks.json | jq '.keys[0].kty'
   ```
4. If the signing key was lost, rotate to a new `JWT_SIGNING_KEY`; all existing
   tokens become invalid (users re‑authenticate via the hosted login).

## 8. Rollback

```bash
helm -n qeet-id rollback qeet-id      # previous release (app image)
kubectl -n qeet-id rollout status deploy/qeet-id
```

**Do not** roll the schema back. Because migrations are expand/contract, the
previous app version still works against the newer schema. If a migration itself
is bad, fix forward with a new migration.

## 9. Validate the chart locally

```bash
# With Helm (or via Docker: docker run --rm -v "$PWD/deploy/helm/qeet-id":/c alpine/helm lint /c)
helm lint deploy/helm/qeet-id
helm template qeet-id deploy/helm/qeet-id --set config.APP_BASE_URL=https://app.acme.com | kubectl apply --dry-run=client -f -
```
