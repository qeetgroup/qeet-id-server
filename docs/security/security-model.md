# Security Model

## Trust boundaries

Qeet ID operates with the following trust levels:

```
Untrusted (internet)
  │
  ├─ Public endpoints  (/v1/auth/login, /v1/auth/signup, /v1/recovery/*)
  │  → Rate-limited, HIBP-checked, bot-scored
  │
Authenticated (valid Bearer JWT or API key)
  │
  ├─ End users         (actor_type=user, tenant-scoped)
  │  → RBAC-enforced, per-user rate limit
  │
  ├─ Org admins        (actor_type=user, elevated role)
  │  → Full tenant management permissions
  │
  ├─ API keys          (actor_type=service, scope-limited)
  │  → Bypass RBAC; own rate limit; no refresh
  │
  ├─ Service accounts  (actor_type=service, client_credentials)
  │  → Machine-to-machine; scope-limited JWT
  │
  └─ AI agents         (actor_type=agent, ephemeral)
     → Short-lived (≤1h), scoped, re-minted per task
```

## Attack surface

| Surface | Defense |
|---|---|
| Login endpoint | Rate limiting (5/s per IP), account lockout, HIBP breach check, bot scoring |
| Token endpoint | Per-IP and per-tenant rate limits |
| Webhook delivery | HMAC-signed outbound payloads; consumer verifies signature |
| Auth hook reception | Outbound only; Qeet ID is the client; timeout + fail-open/closed |
| OIDC / SAML ACS | State validation, replay detection, assertion expiry checks |
| Agent token endpoint | Agent secret verified (bcrypt); scopes bounded by agent config |
| Admin console | CSRF protection, SameSite=Strict cookie, SecurityHeaders |
| API egress (HIBP, notifier) | Bounded timeouts on all HTTP clients |

## Defense layers

### Perimeter
- **HTTPS only** in production (enforced by `Config.Validate()` — `APP_BASE_URL` on localhost blocked in prod)
- **Security headers** on every response: HSTS, X-Frame-Options: DENY, CSP: default-src 'none', CORP
- **CORS** origin whitelist; wildcard origins blocked in production

### Authentication
- **Password hashing:** bcrypt (not MD5, SHA-1, or unsalted SHA-256)
- **Breach detection:** HIBP k-anonymity API on every password login and signup (fail-open)
- **Lockout:** Configurable brute-force lockout after N failures per tenant
- **Passkeys:** Hardware-bound, phish-resistant (WebAuthn FIDO2)

### Authorization
- **RBAC:** Every authenticated route carries a permission requirement checked by `rbac.Enforce`
- **ReBAC:** Fine-grained resource ownership via Zanzibar-style relation tuples
- **Tenant isolation:** Every SQL query is scoped by `tenant_id`; cross-tenant access is architecturally impossible without explicit membership

### Session security
- **Short access token TTL:** 15 minutes (configurable)
- **Single-use refresh tokens:** Replay of a used refresh token invalidates the entire session
- **CSRF:** Double-submit HMAC cookie + origin check for browser-authenticated requests

### Cryptography
- **JWT signing:** ES256 (ECDSA P-256); no symmetric HS256 for new tokens
- **CSRF tokens:** 32 random bytes + HMAC-SHA256
- **Secrets vault:** AES-256-GCM per-tenant; AWS KMS optional
- **Audit chain:** SHA-256 hash chain (tamper detection)

### Operational
- **Audit log:** Every mutation is audit-logged (hash-chained, tamper-evident)
- **SIEM streaming:** Real-time forwarding to Splunk/Datadog/custom HTTP sinks
- **Threat detection:** Anomaly recording for brute-force, credential stuffing, bot signals
- **Boot-time validation:** Insecure defaults refuse to start outside `SERVICE_ENV=dev`

## Sensitive data handling

| Data type | Storage | Protection |
|---|---|---|
| Passwords | `auth.credentials.hash` | bcrypt, never plaintext |
| Passkey private keys | Device secure enclave | Never leave the device |
| JWT signing private key | Process memory (from env) | Not persisted to DB |
| CSRF HMAC key | Process memory (from env) | Not persisted to DB |
| API key secrets | `auth.api_keys.hash` | SHA-256 hash; plaintext shown once |
| Agent secrets | `platform.agent_credentials.hash` | bcrypt; `agt_` prefix shown once |
| Secrets vault values | `platform.secrets.value` | AES-256-GCM encrypted |
| Refresh tokens | `auth.sessions` | Hashed; single-use |

## Incident classification

| Severity | Examples |
|---|---|
| **Critical** | JWT signing key compromise, DB breach, CSRF bypass |
| **High** | Admin account takeover, brute-force at scale, OIDC token forgery |
| **Medium** | Individual account compromise, webhook secret exposure |
| **Low** | Failed login spike, HIBP service outage, rate limit bypass |

For incident response procedures, see [../runbooks/incident-response.md](../runbooks/incident-response.md).
