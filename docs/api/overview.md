# API Overview

Qeet ID exposes a REST API under `/v1` plus protocol-defined paths for OIDC, SAML, and SCIM. The complete machine-readable contract is at [`api/openapi/`](../../api/openapi/) (OpenAPI 3.1.0).

## Base URLs

| Environment | Base URL |
|---|---|
| Development | `http://localhost:4001` |
| Production | `https://api.id.qeet.in` (or self-hosted root) |

## URL structure

```
/v1/                          — versioned REST API
/.well-known/openid-configuration  — OIDC discovery
/jwks.json                    — OIDC/JWT public key set
/userinfo                     — OIDC userinfo endpoint
/saml/:conn/metadata.xml      — SAML SP metadata
/saml/:conn/acs               — SAML Assertion Consumer Service
/scim/v2/                     — SCIM 2.0 provisioning
/oauth/introspect             — RFC 7662 token introspection
/oauth/token                  — OAuth 2.0 token endpoint
/healthz                      — Liveness probe
/readyz                       — Readiness probe (+ DB check)
/metrics                      — Prometheus metrics
```

## Authentication modes

| Mode | Header / Mechanism | Used by |
|---|---|---|
| Bearer JWT | `Authorization: Bearer <token>` | All authenticated `/v1` endpoints |
| API key | `X-API-Key: qk_<secret>` | Machine-to-machine, bypasses RBAC |
| SCIM bearer | Per-connection bearer in `Authorization` | Enterprise IdP provisioning |
| Client credentials | `POST /oauth/token` with `client_id` + `client_secret` | Service accounts |
| SSO session cookie | `qe_session` (set by SAML/OIDC callback) | Browser-based SSO flows |

API keys and service principal tokens bypass route-level RBAC. Their access is controlled by scopes embedded in the token itself.

## Obtaining a token

### User login
```bash
curl -X POST https://api.id.qeet.in/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@acme.test","password":"Password123!","tenant_slug":"acme"}'
```

### API key
API keys are created in the admin console (Developer → API Keys) or via `POST /v1/api-keys`. Include in every request:
```
X-API-Key: qk_<your_secret>
```

### Service account (client credentials)
```bash
curl -X POST https://api.id.qeet.in/oauth/token \
  -d "grant_type=client_credentials&client_id=<id>&client_secret=<secret>&scope=users:read"
```

## Rate limits

| Principal type | Rate | Burst |
|---|---|---|
| Per-IP (public endpoints) | 5 req/s | 20 |
| Per-tenant | 100 req/s | 500 |
| Per-user | 30 req/s | 100 |
| Per-API-key | 50 req/s | 200 |

Rate limit responses use HTTP 429 with a `Retry-After` header (seconds until the next token refills).

## Common headers

| Header | Direction | Purpose |
|---|---|---|
| `Authorization` | Request | Bearer token or Basic auth |
| `X-API-Key` | Request | API key authentication |
| `X-CSRF-Token` | Request | CSRF token for cookie-authenticated browser requests |
| `X-Request-ID` | Response | Unique request identifier (set by `RequestID` middleware if not provided) |
| `Content-Type: application/json` | Both | Required for JSON bodies |

## Response format

Successful responses return the requested resource directly (no envelope). Example:
```json
{ "id": "01J...", "email": "alice@acme.test", "display_name": "Alice" }
```

List responses:
```json
{ "items": [...], "next_cursor": "eyJ..." }
```

Error responses: see [errors.md](errors.md).

## OpenAPI spec and Postman

- **OpenAPI 3.1.0:** [`api/openapi/`](../../api/openapi/)
- **Postman collection:** [`api/postman/qeet-id.postman_collection.json`](../../api/postman/qeet-id.postman_collection.json)
- **Run Postman tests:** `make test-api FOLDER=Auth` (requires running API)

The OpenAPI spec is coverage-guarded by CI — every mounted route must appear in the spec.
