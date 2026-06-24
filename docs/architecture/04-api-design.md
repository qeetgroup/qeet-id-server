# API Design

## URL structure

| Surface | Base path | Notes |
|---|---|---|
| REST API | `/v1/` | Versioned; all application endpoints |
| OIDC discovery | `/.well-known/openid-configuration` | Spec-defined path |
| JWKS | `/jwks.json` | Public key set for JWT verification |
| SAML metadata | `/metadata.xml` | Per-connection at `/saml/:conn/metadata.xml` |
| SAML ACS | `/saml/:conn/acs` | Assertion Consumer Service |
| SCIM provisioning | `/scim/v2/` | RFC 7644; per-tenant bearer token |
| LDAP bind | `/ldap/` | (root level) |
| Health / readiness | `/healthz`, `/readyz` | Kubernetes probes |
| Metrics | `/metrics` | Prometheus scrape |

## Authentication modes

| Mode | How it works | Used by |
|---|---|---|
| **Bearer JWT** | `Authorization: Bearer <access_token>` | All authenticated `/v1` endpoints |
| **API key** | `X-API-Key: qk_<secret>` | Machine-to-machine calls; bypasses RBAC, has own rate limit |
| **SCIM bearer** | Per-connection bearer token in `Authorization` | SCIM provisioning from enterprise IdPs |
| **Client credentials** | OAuth 2.0 `client_credentials` grant | Service accounts obtaining JWT access tokens |
| **SSO cookie** | `qe_session` cookie (SAML/OIDC callback flows) | Browser SSO redirect flows |

Bearer JWT and API key can be used interchangeably on most endpoints. RBAC enforcement applies only to user JWTs — API keys and service principals bypass route-level RBAC and are instead scoped by the permissions encoded in the token.

## OpenAPI contract

The complete API contract lives under [`api/openapi/`](../../api/openapi/) — five self-contained, bounded-context OpenAPI 3.1 documents (`auth`, `management`, `federation`, `developer`, `operations`). A Postman collection is at [`api/postman/`](../../api/postman/). Tools that want one document merge them with `go run ./tools/openapi-split merge`.

**Enforcement:** [`platform/api/rest/openapi_coverage_test.go`](../../platform/api/rest/openapi_coverage_test.go) runs in `go test ./...` and fails if any mounted route is absent from the specs (it reads the **union** of all five files). Adding a new route **requires** documenting it in the matching file in the same change or CI will block the PR.

```bash
make test-api FOLDER=Auth   # run Postman/Newman against a live backend, scoped by folder
```

## Error envelope

All API errors use a single stable JSON shape:

```json
{
  "error": {
    "code":       "not_found",
    "message":    "User not found",
    "detail":     "No user exists with id 01J...",
    "request_id": "req_01J..."
  }
}
```

| Field | Description |
|---|---|
| `code` | Machine-readable error code (snake_case) |
| `message` | Human-readable summary |
| `detail` | Additional context for debugging (optional) |
| `request_id` | Correlates to access log; include when reporting issues |

**HTTP status → code mapping:**

| Status | `errs` sentinel | `code` value |
|---|---|---|
| 400 | `ErrBadRequest` | `bad_request` |
| 401 | `ErrUnauthorized` | `unauthorized` |
| 403 | `ErrForbidden` | `forbidden` |
| 404 | `ErrNotFound` | `not_found` |
| 409 | `ErrConflict` | `conflict` |
| 422 | `ErrUnprocessable` | `unprocessable` |
| 429 | `ErrTooManyRequests` | `too_many_requests` |
| 500 | `ErrInternal` | `internal` |
| 501 | `ErrNotImplemented` | `not_implemented` |

**Documented deviations:**
- **SCIM** (`/scim/v2`) uses the RFC 7644 envelope (`schemas`/`status`/`detail`). Required for compatibility with enterprise IdP provisioning agents.
- **SAML** success paths return XML (metadata) or HTTP 302 with auto-submit HTML form (POST binding). SAML _errors_ use the standard JSON envelope.

Do not use `http.Error()` for API responses — it emits plain text and breaks the envelope.

## Middleware chain

Request processing order (see [`platform/api/rest/router.go`](../../platform/api/rest/router.go)):

```
RequestID → RealIP → Recoverer → InFlight → SecurityHeaders
  → AccessLog → Tracing → Metrics → CSRF → CORS
    → [route group middleware: API key auth, RequireAuth, rate limits, RBAC]
      → handler
```

Security headers applied to every response:
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'none'`
- `Cross-Origin-Resource-Policy: same-origin`
- `Permissions-Policy: (all restricted except WebAuthn)`

## Rate limits

| Key type | Rate | Burst | Applied to |
|---|---|---|---|
| Per-IP | 5 req/s | 20 | Login, signup, recovery endpoints (public) |
| Per-tenant | 100 req/s | 500 | All authenticated endpoints |
| Per-user | 30 req/s | 100 | Authenticated user requests |
| Per-API-key | 50 req/s | 200 | API key authenticated requests |

Rate limiting is token-bucket (in-process or Redis-backed). Exceeds return `429 Too Many Requests` with a `Retry-After` header. The limiter **fails open** on store errors — a Redis outage never locks traffic.

## Pagination

List endpoints use **opaque keyset cursors** via [`platform/api/rest/paging`](../../platform/api/rest/paging/).

**Request:**
```
GET /v1/users?limit=50&after=<cursor>
```

**Response:**
```json
{
  "items": [...],
  "next_cursor": "eyJ..."
}
```

Cursors are base64-encoded and must be treated as opaque strings. Sorting is stable and deterministic (typically by `created_at DESC, id DESC`). When `next_cursor` is absent, the result set is exhausted.

## Versioning

The API is currently at **v0.2.0** (pre-1.0). The `/v1` prefix is reserved for the stable 1.0 release. Breaking changes before GA are made without a version bump; after 1.0, breaking changes will increment the major version.
