# qeet-id — Operations Runbook

Operational procedures for deploying and running Qeet ID. Pair with
[../README.md](../README.md) (architecture) and the security policy in
[../SECURITY.md](../SECURITY.md).

## Topology

- **Backend**: stateless Go service, listens on `HTTP_PORT` (default 4001), exposes
  `/healthz`, `/readyz`, `/metrics`. Scale horizontally; `REDIS_URL` makes rate
  limits correct across replicas.
- **Datastores**: PostgreSQL (primary), Redis (rate limits / shared state).
- **Edge**: TLS-terminating reverse proxy (Caddy in Compose; Ingress + cert-manager in k8s).
- **Boot gate**: `config.Validate()` refuses to start outside `SERVICE_ENV=dev` if any
  production invariant is unmet (weak `JWT_SECRET`, missing `JWT_SIGNING_KEY`/secrets,
  wildcard `ALLOWED_ORIGINS`, localhost `APP_BASE_URL`, CSRF disabled). A CrashLoopBackOff on
  first deploy is almost always a failed invariant — read the logs.

## Required secrets

| Key | What | Notes |
| --- | --- | --- |
| `DB_URL` | Postgres DSN (contains password) | RDS endpoint in prod |
| `JWT_SECRET` | ≥32-char random | `openssl rand -base64 48` |
| `JWT_SIGNING_KEY` | EC P-256 private key (PEM) | ES256 token signing; rotate per below |
| `JWT_RETIRED_KEYS` | concatenated PEM public keys | rotation grace window (optional) |
| `SECRETS_KEY` *or* `SECRETS_WRAPPED_DEK` | vault DEK | static base64 key, **or** KMS-wrapped blob when `SECRETS_PROVIDER=aws-kms` |
| `KMS_KEY_ID` | KMS key ARN | with `SECRETS_PROVIDER=aws-kms` |
| `SAML_IDP_KEY` / `SAML_IDP_CERT` | RSA key + X.509 cert (PEM) | stable IdP signing identity |
| `SMTP_PASSWORD`, `TWILIO_AUTH_TOKEN` | provider creds | optional; log-only fallback if unset |

Compose: export secrets in the shell (multiline PEMs survive); non-secret config goes in
`.env.prod`. Kubernetes: `secrets.existingSecret`, or `externalSecrets.enabled` (AWS Secrets
Manager via External Secrets Operator, the prod default).

## Build & release flow

1. Merge conventional-commit PRs to `main` → **release-please** opens/updates a release PR.
2. Merge the release PR → it bumps the version, updates `CHANGELOG.md`, and pushes tag `vX.Y.Z`.
3. `release.yml` builds + pushes **signed** (cosign keyless) images with SBOM + provenance:
   `ghcr.io/qeetgroup/qeet-id:X.Y.Z` and `…/qeet-id-migrate:X.Y.Z`.
4. Verify a signature before promoting:
   ```bash
   cosign verify ghcr.io/qeetgroup/qeet-id:X.Y.Z \
     --certificate-identity-regexp 'https://github.com/qeetgroup/qeet-id/.*' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

## Deploy

### Staging (Docker Compose)
```bash
cd deploy/compose
cp .env.prod.example .env.prod                 # fill non-secret config
export JWT_SECRET=… JWT_SIGNING_KEY="$(cat signing.pem)" SECRETS_KEY=… \
       SAML_IDP_KEY="$(cat idp.key)" SAML_IDP_CERT="$(cat idp.crt)" POSTGRES_PASSWORD=…
export QEETID_IMAGE=ghcr.io/qeetgroup/qeet-id:X.Y.Z \
       QEETID_MIGRATE_IMAGE=ghcr.io/qeetgroup/qeet-id-migrate:X.Y.Z
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d
```
The `migrate` one-shot applies schema before `backend` starts.

### Production (Helm)
```bash
helm upgrade --install qeet-id deploy/helm/qeet-id \
  -n qeet-id --create-namespace \
  -f deploy/helm/qeet-id/values-prod.yaml \
  --set image.tag=X.Y.Z --set migrate.image.tag=X.Y.Z
kubectl -n qeet-id rollout status deploy/qeet-id
```
The pre-upgrade migration **Job** runs `migrate … up` before the new pods roll. If it fails, the
release is aborted and the old pods keep serving.

## Rollback

- **Kubernetes**: `helm rollback qeet-id <REVISION> -n qeet-id` (see `helm history qeet-id`).
  ⚠️ Roll back the **app** freely; do **not** auto-revert DB schema — see migrations below.
- **Compose**: re-point `QEETID_IMAGE` to the previous tag and `up -d`.
- Images are immutable + signed; always pin a known-good `X.Y.Z`, never `latest`.

## Database migrations

Migrations are golang-migrate SQL pairs in `migrations/` (never edit an applied one —
add a new pair). The `qeet-id-migrate` image bakes them in.

```bash
# Forward (normally automatic via the Job / Compose one-shot):
docker run --rm qeet-id-migrate:X.Y.Z -database "$DB_URL" up
# Roll back the last migration (only if its .down.sql is safe & reversible):
docker run --rm qeet-id-migrate:X.Y.Z -database "$DB_URL" down 1
# Recover a 'dirty' state after a half-applied migration:
docker run --rm qeet-id-migrate:X.Y.Z -database "$DB_URL" force <VERSION>
```
**Rule:** prefer roll-forward fixes. Schema rollback during an incident risks data loss; restore
from PITR instead if a migration corrupted data.

## Key & secret rotation

### JWT signing key (target: every 90 days)
ES256 verification supports a retired-key grace window, so rotation is zero-downtime:
1. Generate a new EC P-256 key; extract its **public** key (PEM).
2. Append the **old public** key to `JWT_RETIRED_KEYS` (still verifiable; never re-signed).
3. Set `JWT_SIGNING_KEY` = the new private key; redeploy.
4. After the grace window (≥ refresh-token TTL, default 30d) drop the old key from `JWT_RETIRED_KEYS`.

### Vault data key (`SECRETS_KEY` / KMS)
- With `aws-kms`, enable **automatic key rotation** on the CMK; `kms.Decrypt` transparently handles
  prior key material, so the wrapped DEK keeps working. Rotating the **DEK itself** requires
  re-encrypting stored secrets — a planned maintenance task, not an incident action.
- With `static`, rotating `SECRETS_KEY` invalidates existing vault ciphertext; coordinate a
  re-encryption migration before changing it.

### SAML IdP cert
Rotate `SAML_IDP_KEY`/`SAML_IDP_CERT` before expiry and re-publish IdP metadata so SPs re-import it.

## Backup & DR (AWS RDS)

- Enable **automated backups** + **PITR** (continuous WAL); set retention ≥ 7 days.
- Take a manual snapshot before any risky migration or major release.
- **Restore drill (quarterly):** restore the latest snapshot to a scratch instance, point a
  staging deploy at it, run smoke tests. Record RTO/RPO actuals.
- Redis is rebuildable (rate-limit/ephemeral state) — no backup required; on loss, limits reset.

## Incident response

1. **Triage** with the Grafana dashboard + alerts (`deploy/observability/`): error rate, p99
   latency, target down, goroutines.
2. **App won't boot** → `config.Validate()` failure; the log names the exact invariant. Fix the
   env/secret and redeploy.
3. **5xx spike** → check recent release (`build_info` version), DB/Redis readiness (`/readyz`
   breakdown), and downstream timeouts (SMTP/Twilio/HIBP). Roll back the app if release-correlated.
4. **DB issues** → check connection pool saturation (`DB_MAX_CONNS`), then RDS metrics; fail over /
   restore from PITR if corruption is suspected.
5. Report vulnerabilities per [../SECURITY.md](../SECURITY.md).
