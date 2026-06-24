# Incident Response Runbook

## Severity levels

| Level | Definition | Response time |
|---|---|---|
| **P0 — Critical** | Active data breach, JWT key compromise, service down | Immediately |
| **P1 — High** | Admin account takeover, brute-force at scale, auth unavailable | < 30 minutes |
| **P2 — Medium** | Individual account compromise, webhook secret exposed | < 2 hours |
| **P3 — Low** | HIBP outage, elevated error rate, non-critical feature broken | < 24 hours |

---

## Compromised API key

**Detection:** Customer reports unusual activity, or SIEM alert on unexpected API key usage.

```bash
# Immediately revoke the key
DELETE /v1/api-keys/:id
Authorization: Bearer <admin token>

# Audit log — what did this key do?
GET /v1/audit?actor_id=<api_key_id>&from=<suspected_start>
```

Create a replacement key for the customer:
```
POST /v1/api-keys
{ "name": "replacement-key", "scopes": [...] }
```

The compromised key's secret is bcrypt-hashed in the DB — there is no way to recover the plaintext. Issue a new key.

---

## Compromised user account

**Detection:** User reports unexpected activity; anomaly detection alert; threat.detected audit event.

```bash
# 1. Suspend the account (blocks login immediately)
POST /v1/users/:id/suspend
Authorization: Bearer <admin token>

# 2. Revoke all active sessions
DELETE /v1/users/:id/sessions
Authorization: Bearer <admin token>

# 3. Audit log — what happened?
GET /v1/audit?actor_id=<user_id>&from=<suspected_start>&limit=100

# 4. After investigation, restore access and reset password
POST /v1/users/:id/unsuspend
POST /v1/users/:id/force-password-reset
```

---

## Compromised JWT signing key

**Severity: P0** — an attacker with the signing key can mint arbitrary valid JWTs for any user.

```bash
# 1. IMMEDIATELY: Generate a new signing key
# New key must be EC P-256 (see platform/security/jwt for key generation)

# 2. Deploy with the new JWT_SIGNING_KEY environment variable
# Both old and new keys serve in JWKS during the grace window

# 3. The old key's tokens expire within 15 minutes (access token TTL)
# After 15 minutes, remove the old key from the configuration

# 4. Force all users to re-authenticate (invalidate all refresh tokens)
# This requires a migration or admin tool — file an issue if needed

# 5. Audit: check audit log for logins from suspicious user IDs
GET /v1/audit?action=login.succeeded&from=<start_of_compromise>
```

**Important:** A compromised signing key means all existing tokens are untrusted. Move quickly — the 15-minute access token TTL is your window.

---

## Brute-force attack in progress

**Detection:** Prometheus alert on 429 rate; SIEM alert on `login.failed` spike; threat.detected events.

```bash
# Check current rate-limit metrics
curl https://api.id.qeet.in/metrics | grep http_requests_total | grep 429

# Add IP denylist rule (immediate effect)
POST /v1/ip-rules
Authorization: Bearer <admin token>
{ "cidr": "203.0.113.0/24", "action": "deny" }

# Check which accounts are targeted
GET /v1/audit?action=login.failed&from=<start>
```

For large-scale attacks, escalate to cloud CDN/WAF level IP blocking — more efficient than per-IP rules in Qeet ID.

Account lockout is automatic after N failed attempts — check the tenant's lockout configuration in the admin console under Access → Auth Policy.

---

## CSRF bypass suspected

**Symptoms:** Admin reports unexpected changes made from their session; suspicious mutations in audit log without expected actors.

```bash
# 1. Check audit log for suspicious mutations without CSRF-expected context
GET /v1/audit?action=user.updated&from=<suspected_time>

# 2. Verify ALLOWED_ORIGINS is not too broad
# Check config — wildcard origins should be impossible in prod (Config.Validate blocks it)

# 3. Check if qe_csrf cookie is being set on all GET responses
curl -v https://api.id.qeet.in/v1/users -H "Authorization: Bearer <token>" 2>&1 | grep qe_csrf

# 4. Review CSRF exempt path list in platform/api/rest/middleware/csrf.go
# Verify no new paths were inadvertently added to exemptions
```

If a genuine bypass is found:
1. Rotate `CSRF_KEY` (rolling — existing users get new cookie on next GET)
2. Force re-authentication for all users
3. Investigate how the bypass occurred

---

## Hash chain integrity failure

**Detection:** `GET /v1/audit/verify` returns `{ "valid": false, ... }`

**Severity: P0** — indicates database tampering.

```bash
GET /v1/audit/verify
# Response: { "valid": false, "broken_at_event_id": "01J...", "tenant_id": "01J..." }
```

Steps:
1. Preserve DB state — take an immediate snapshot/backup before any changes
2. Identify the broken event and compare with SIEM forwarded copies (if a SIEM sink was configured)
3. Identify all DB access in the timeframe using PostgreSQL audit logs or cloud DB access logs
4. Escalate to security review — this indicates unauthorized DB write access

The audit log is append-only in application code. A broken chain means either:
- A bug in the chain-writing code (rare; check recent deployments)
- Direct database modification (serious security incident)

---

## Service down (`/readyz` returning 503)

```bash
# Check readyz
curl https://api.id.qeet.in/readyz

# If DB unreachable — check DB status
kubectl get pods -n qeet-id   # look for DB-related pods
# Or check RDS/Cloud SQL console

# If pods are crashing — check logs
kubectl logs -n qeet-id deploy/qeet-id --previous
# Look for Config.Validate() failures (misconfigured env var)
# or migration version mismatch errors

# If migration is blocking
kubectl get jobs -n qeet-id   # check migration job status
kubectl logs -n qeet-id job/<migration-job-name>
```

Common causes:
- `Config.Validate()` failure — a required env var is missing or insecure
- Migration failed mid-run — dirty state (see [database-operations.md](database-operations.md))
- Database connectivity — check `DATABASE_URL`, network policies, DB instance status
