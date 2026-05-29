# Qeet ID — API Design Standards

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | API Design Standards |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Backend Lead + API Designer |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the public and internal API standards every Qeet ID-built service must follow. It covers URL conventions, HTTP method semantics, authentication scheme, header conventions, request and response body format, pagination, filtering, error response format, rate-limit headers, versioning and deprecation policy, webhook payload conventions, OpenAPI specification requirements, SDK-friendliness considerations, and documentation auto-generation.

This document is the contract between every Qeet ID service author and every Qeet ID customer. The six MVP SDKs (React, Next.js, Node.js, Python, Flutter, Go — Charter §5) are generated against or hand-written against the OpenAPI specs that conform to this document. A service that ships an endpoint that violates these standards ships an SDK incompatibility, a documentation defect, and a customer migration cost.

The audience is the Backend Engineering Lead, every service author, the API Designer, every SDK engineer, the Technical Writers, and Developer Relations.

This document depends on [Microservices Decomposition](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md), [Authorization Engine Design](Qeet ID%20%E2%80%94%20Authorization%20Engine%20Design.md), and [Multi-Tenancy Architecture](Qeet ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md).

---

### 3. API Design Principles

**AP-01 — REST first.** All public APIs are REST over HTTPS. GraphQL is explicitly deferred (ADR-007). The trade-off: REST has wider SDK and tooling support, simpler caching, simpler authorization, mature observability, and lower learning cost for the 6 SDK languages.

**AP-02 — OpenAPI 3.1 is the single source of truth.** Specs live next to the service code; CI gates every PR for spec/code drift. SDK generation, mock servers, and API explorers are all driven by these specs (NFR IO-07; Compliance OI-03 indirectly).

**AP-03 — Resource-oriented URLs.** Nouns, not verbs. Verbs come from HTTP methods.

**AP-04 — Versioned URIs.** `/v1/` today; `/v2/` only when a non-backwards-compatible change is unavoidable. Twelve-month overlap minimum (NFR AR-03 / AR-04).

**AP-05 — Stable contracts.** Adding a field is allowed; removing or repurposing is breaking. Adding an enum value is breaking unless every consumer documented how it handles unknown values from the outset (the SDKs do).

**AP-06 — Predictable shape.** Consistency wins. `users.created_at` is a timestamp. Anywhere else there is a `created_at`, it is a timestamp. Field names are `snake_case`. IDs are strings (UUIDs serialised as strings, prefixed where helpful).

**AP-07 — Errors are first-class.** Every API endpoint documents its error shape. Errors use RFC 7807 `application/problem+json` (with Qeet ID extensions; §11).

**AP-08 — Idempotency.** Every state-changing endpoint supports `Idempotency-Key` (where it makes sense) or has an intrinsic dedup key (e.g., `externalId` for SCIM).

**AP-09 — Pagination, not unbounded lists.** Every list endpoint paginates. Default page size is finite. Cursors over offsets.

**AP-10 — Documentation is part of the API.** Every endpoint has examples; every error has a description; every breaking-change history is recorded.

**AP-11 — Customer security-friendly by default.** Tokens never in URLs (Protocol OS-14). PII never in URLs. Long-lived sensitive data never in GET requests.

**AP-12 — Conform to the protocols.** OAuth, OIDC, SAML, SCIM, WebAuthn endpoints follow their respective standards, not Qeet ID conventions. Where the standards disagree with these conventions, the standards win.

---

### 4. URL Conventions

### 4.1 Host

| Surface | Host pattern | Notes |
| --- | --- | --- |
| Tenant API | `https://{tenant-slug}.qeetify.com/v1/...` | Tenant slug subdomain — also used for OAuth issuer URL |
| Tenant OAuth | `https://{tenant-slug}.qeetify.com/oauth/...` | Per Protocol DC-01 |
| Tenant SAML | `https://{tenant-slug}.qeetify.com/saml/...` | Tenant in path of the connection ID |
| Tenant SCIM | `https://{tenant-slug}.qeetify.com/scim/v2/...` | SCIM 2.0 standard path |
| Tenant Hosted Login | `https://{tenant-slug}.qeetify.com/login/...` | Branded per tenant |
| Customer-shared API host | `https://api.qeetify.com/v1/...` | Global account/admin operations |
| Developer Portal | `https://qeetify.com/docs`, `https://qeetify.com/api` | |
| Status Page | `https://status.qeetify.com` | |

### 4.2 Path Structure

```
   /v1/{resource}                 List & create
   /v1/{resource}/{id}            Single resource
   /v1/{resource}/{id}/{sub}      Sub-resource
   /v1/{resource}/{id}/{sub}/{sub_id}
```

Examples:

```
   /v1/users                                  List users; create user
   /v1/users/user_8f3                          Get / patch / delete user
   /v1/users/user_8f3/sessions                 List a user's sessions
   /v1/users/user_8f3/sessions/sess_1a         Revoke a session
   /v1/organizations/{id}/applications         Apps in an org
   /v1/applications/{client_id}/secrets        Rotate a client secret
```

### 4.3 Resource Naming

- **Plural nouns.** `users`, `roles`, `applications`, `webhooks`, `api-keys`. Even for singleton-like resources (`/v1/organizations/current`).
- **Kebab case in URLs.** `api-keys` not `api_keys` or `apiKeys`. Reserved for the URL surface; bodies use `snake_case`.
- **Stable identifiers.** Use the canonical resource id (`user_8f3...`), not the customer's external id or email.

### 4.4 Identifier Format

- All Qeet ID-generated IDs are **prefixed** for readability and grep-ability: `user_`, `org_`, `client_`, `key_`, `sess_`, `tok_`, `role_`, `perm_`, `conn_`, `wh_`, `sub_`, `inv_`.
- Internal storage is UUID v7; wire format is the prefix + `base32hex` of the UUID bytes. Example: `user_01HX2K3M4N5P6Q7R8S9T0V1W2X`.
- This pattern is also used by Stripe (`cus_`, `ch_`, etc.) and customers expect it.

### 4.5 Filter, Pagination, Sort Query Parameters

```
   GET /v1/users
     ?email=alice@example.com           — exact-match filter
     ?status=active                     — enum filter
     ?created_after=2026-01-01T00:00:00Z — range filter
     ?cursor=eyJ...                     — pagination
     ?limit=50                          — page size
     ?sort=-created_at,email            — sort: prefix - for descending
     ?fields=id,email,name              — sparse fieldset (optional, recommended)
```

---

### 5. HTTP Method Semantics

| Method | Use | Idempotency | Body |
| --- | --- | --- | --- |
| GET | Read | Idempotent (no side effects) | No body |
| POST | Create / non-idempotent action | Not idempotent unless `Idempotency-Key` | Body |
| PUT | Full replace | Idempotent | Body |
| PATCH | Partial update (RFC 7396 / JSON Merge Patch) | Idempotent | Body |
| DELETE | Delete | Idempotent | Optional |
| OPTIONS | CORS preflight | Idempotent | — |
| HEAD | Same as GET without body | Idempotent | — |

Notes:

- **PATCH semantics:** JSON Merge Patch (RFC 7396) by default. SCIM uses RFC 6902 JSON Patch (because the spec requires it; Protocol §7.5).
- **POST for actions:** for endpoints that don't fit pure CRUD (`/v1/roles/{id}/permissions`, `/v1/applications/{id}/rotate-secret`), POST is the right method.

---

### 6. Authentication Scheme

### 6.1 Bearer Token

All public-API authentication is via the OAuth 2.0 bearer token:

```
   Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

The token may be:

- A user-context access token (issued by Authorization Code + PKCE flow).
- A service-account access token (issued by Client Credentials flow).
- An API key in `qf_live_*` / `qf_test_*` form, accepted as a bearer token when explicitly permitted by the endpoint (e.g., management APIs).

### 6.2 API Keys vs Tokens

- API keys are long-lived (until rotated/revoked). They are presented as bearer tokens against management endpoints (NFR IC-05 path; Protocol AK-*).
- Tokens are short-lived. They are presented as bearer tokens against application endpoints.
- Endpoints document which they accept; most accept both, with auditing distinguishing them.

### 6.3 No Basic Auth, No Token in URL

Basic auth is not supported (Compliance EN-01 + Protocol OS-14). Tokens in URLs are forbidden — only in `Authorization` header.

### 6.4 mTLS

Public APIs do not require mTLS at MVP. Mutual TLS for service-to-service is internal (Microservices §6.1; ADR-013).

---

### 7. Standard Headers

### 7.1 Request Headers

| Header | Required | Purpose |
| --- | --- | --- |
| `Authorization` | Yes (auth'd endpoints) | Bearer token |
| `Content-Type` | Required on bodies | `application/json` for the default; SCIM uses `application/scim+json` |
| `Accept` | Optional | Defaults to JSON variant of resource |
| `Accept-Language` | Optional | `en`, `es`, etc. — for localised messages and emails |
| `X-Request-ID` | Optional (server generates if absent) | Client correlation; server echoes back |
| `Idempotency-Key` | Optional but recommended on POST/PATCH | Up to 256-char string; deduplicates retried writes for 24 h (NFR ID-02) |
| `User-Agent` | Required (per HTTP standard) | Used for observability and bot detection |

### 7.2 Response Headers

| Header | Purpose |
| --- | --- |
| `X-Request-ID` | Echo (or generated) — for support tickets |
| `Content-Type` | `application/json` |
| `Cache-Control` | `no-store` on default; specific values on cacheable resources (JWKS, discovery doc) |
| `X-RateLimit-Limit` | The applicable limit |
| `X-RateLimit-Remaining` | Remaining requests in the current window |
| `X-RateLimit-Reset` | UNIX timestamp when the window resets |
| `Retry-After` | On 429/503 — seconds to wait |
| `Deprecation` | Per RFC 9745 — date the endpoint deprecates |
| `Sunset` | Per RFC 8594 — date the endpoint stops working |
| `Link` | Per RFC 8288 — relations (next page, deprecation announcement, etc.) |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` (NFR SE-04) |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` (NFR AS-08) |

### 7.3 Tenant Header (Internal Only)

`X-Qeetify-Tenant-Id` is set by the API Gateway from the bearer token claim and propagated internally (Multi-Tenancy §9). It is **never accepted from clients**; client-supplied values are overwritten.

---

### 8. Request / Response Body Format

### 8.1 JSON, snake_case, Stable Shape

```json
{
  "id": "user_01HX...",
  "tenant_id": "org_acme",
  "email": "alice@example.com",
  "email_verified": true,
  "name": {
    "given_name": "Alice",
    "family_name": "Lee"
  },
  "status": "active",
  "created_at": "2026-05-19T12:34:56Z",
  "updated_at": "2026-05-19T12:34:56Z"
}
```

- Timestamps: ISO 8601 UTC with `Z` suffix. No timezone offsets in bodies (clients localise on display).
- Money: object with `amount` (integer cents) and `currency` (ISO 4217). E.g. `{"amount": 1999, "currency": "USD"}`.
- Booleans: `true` / `false`. Never `0` / `1`.
- Empty values: `null` for "intentionally absent / unset"; omit the key for "no value yet". The OpenAPI spec documents per-field expectations.
- Enums: lowercase snake_case strings. SDK clients deserialize unknown enum values into a `unknown` sentinel rather than crashing — forward compatibility for adding new enum values.

### 8.2 Field Order

OpenAPI specs document a canonical field order: `id`, `tenant_id`, business fields, `metadata`, `created_at`, `updated_at`. Servers should emit fields in this order; SDKs do not depend on it but readability matters.

### 8.3 Metadata

Optional `metadata` object on resources where customers commonly need it (`users`, `applications`, `webhooks`, `subscriptions`). Up to 50 keys, 500 chars each, customer-defined.

### 8.4 Common Top-Level Shapes

**Single resource:**

```json
{ "id": "...", "type": "user", ...fields }
```

**List response:**

```json
{
  "object": "list",
  "data": [ {...}, {...} ],
  "has_more": true,
  "next_cursor": "eyJ..."
}
```

**Created response:**

```http
HTTP/1.1 201 Created
Location: /v1/users/user_01HX...
Content-Type: application/json

{ ...the created resource... }
```

---

### 9. Pagination

### 9.1 Cursor-Based, Not Offset

Cursor pagination is forward-only and stable under writes (which offset pagination is not):

```
   GET /v1/users?limit=50

   200 OK
   {
     "object": "list",
     "data": [ ...50 users... ],
     "has_more": true,
     "next_cursor": "eyJ..."
   }

   GET /v1/users?limit=50&cursor=eyJ...
```

The cursor is an opaque base64-encoded payload that the server interprets. It typically contains the last seen ID and the sort tuple. Clients must not attempt to interpret it.

### 9.2 Limits

| Endpoint class | Default `limit` | Max `limit` |
| --- | --- | --- |
| User-facing list endpoints | 50 | 200 |
| Bulk export endpoints | 100 | 1000 |
| Audit search | 100 | 500 |
| SCIM list | 100 (per SCIM spec) | 500 |

### 9.3 Total Count

We do **not** return a total count on regular list endpoints — it forces a second query and is rarely worth the latency. A separate `/count` sub-endpoint is provided where customers genuinely need it (e.g., dashboard summary cards).

---

### 10. Filtering & Sorting

### 10.1 Equality and Range

```
   GET /v1/users?email=alice@example.com
   GET /v1/users?status=active
   GET /v1/users?created_after=2026-01-01T00:00:00Z
   GET /v1/users?created_before=2026-06-01T00:00:00Z
   GET /v1/users?status=active,suspended    — comma-separated for IN
```

### 10.2 Searching

Search endpoints expose a separate path (`/v1/users/search`) when the query is full-text or complex enough to deserve POST. GET is preserved for simple filtering.

### 10.3 Sorting

`?sort=field,-other_field`. Single ascending field is the default. Prefix `-` for descending. Multi-key sort is comma-separated. SDKs surface this as a typed parameter.

### 10.4 Sparse Fieldsets

`?fields=id,email,name` returns only those fields. Optional — most clients ignore. Useful for high-volume mobile clients.

---

### 11. Error Response Format

### 11.1 RFC 7807 (Problem Details) with Qeet ID Extensions

```http
HTTP/1.1 422 Unprocessable Entity
Content-Type: application/problem+json
X-Request-ID: req_01HX...

{
  "type": "https://qeetify.com/errors/validation",
  "title": "The request was invalid",
  "status": 422,
  "code": "validation_error",
  "detail": "The 'email' field must be a valid email address.",
  "errors": [
    {
      "field": "email",
      "code": "invalid_format",
      "message": "must be a valid email address"
    }
  ],
  "request_id": "req_01HX...",
  "docs_url": "https://qeetify.com/docs/errors/validation_error"
}
```

### 11.2 Error Code Catalog (Selected)

| HTTP | `code` | Meaning |
| --- | --- | --- |
| 400 | `bad_request` | Generic malformed request |
| 400 | `validation_error` | Schema/format validation failed; `errors[]` lists fields |
| 401 | `unauthenticated` | Missing or invalid bearer token |
| 401 | `invalid_token` | Token expired / signature mismatch |
| 403 | `permission_denied` | Authenticated but not authorised for action |
| 403 | `tenant_mismatch` | Token's tenant ≠ requested resource's tenant |
| 404 | `not_found` | Resource doesn't exist (or you can't see it) |
| 409 | `conflict` | Idempotency-Key collision; SCIM duplicate; resource state conflict |
| 422 | `unprocessable_entity` | Validated but logically unprocessable |
| 429 | `rate_limited` | Rate limit exceeded; `Retry-After` set |
| 451 | `legal_hold` | GDPR Article 17 deletion blocked by audit retention |
| 500 | `internal_error` | Unhandled server error; `request_id` for support |
| 502 | `bad_gateway` | Upstream dependency failure |
| 503 | `temporarily_unavailable` | Service degraded; try again |
| 504 | `gateway_timeout` | Upstream timeout |

For OAuth endpoints, the error format follows RFC 6749 / RFC 6750 (not RFC 7807) — `{"error":"invalid_grant","error_description":"..."}` — to maintain protocol conformance.

### 11.3 Anti-Enumeration on Errors

Where revealing whether a resource exists would aid enumeration (especially around users and emails), endpoints return uniform 404 `not_found` regardless of whether the resource is absent or merely inaccessible. The audit log carries the truth.

---

### 12. Rate Limiting

### 12.1 Headers

```
   X-RateLimit-Limit: 6000
   X-RateLimit-Remaining: 4521
   X-RateLimit-Reset: 1747900800
   Retry-After: 12        (only on 429)
```

### 12.2 Limit Classes

Per NFR RL-01..RL-10:

- Per-IP for unauthenticated endpoints.
- Per-`client_id` for token endpoints.
- Per-tenant for authenticated endpoints.
- Per-endpoint class for hot spots (SCIM bulk, audit export).

Limits depend on plan. The dashboard shows current usage and limit per tenant.

### 12.3 Throttling Strategy

429 with `Retry-After`. Never silent timeouts (NFR BT-06). SDKs implement automatic retry with exponential backoff on 429 and 5xx.

---

### 13. Versioning & Deprecation Policy

### 13.1 Versioning Approach

URL versioning (`/v1/`, `/v2/`). Header-based versioning is rejected — it complicates SDKs, caching, and discoverability.

A new **major** version is introduced only when a non-backwards-compatible change is necessary:

- A breaking schema change (renaming a field, removing a field, changing the type).
- A breaking semantics change (changing what an endpoint returns).
- A breaking authorization change.

**Adding** a field, an endpoint, an enum value (when documented as forward-compatible), an optional query parameter, or a new HTTP method is **non-breaking** and ships within `/v1/`.

### 13.2 Deprecation Process

Per NFR AR-04:

1. **Announce** the deprecation in the changelog and email to all impacted application owners.
2. **Mark** responses with `Deprecation: <date>` (RFC 9745) and `Sunset: <date>` (RFC 8594) headers.
3. **Document** the migration path with code examples.
4. **Maintain** the deprecated endpoint for at least 12 months (NFR AR-03).
5. **Remove** the endpoint on the sunset date. After sunset, the endpoint returns 410 Gone with a migration pointer.

### 13.3 SDK Versioning

SDKs are versioned independently (semantic versioning). An SDK targets one or more API major versions; the SDK changelog states which.

---

### 14. Webhook Payload Standards

### 14.1 Event Envelope

```json
{
  "id": "evt_01HX...",
  "type": "user.created",
  "tenant_id": "org_acme",
  "created_at": "2026-05-19T12:34:56Z",
  "api_version": "v1",
  "data": {
    "object": { ...the resource at time of event... }
  }
}
```

### 14.2 Signing

HMAC-SHA256 (Compliance Matrix IC-05; Feature scope). Header:

```
   Qeetify-Signature: t=1747900800,v1=8a9b...,v0=...
```

- `t` = unix timestamp the signature was created.
- `v1` = base16 HMAC-SHA256 of `t.payload` using the subscription's signing secret.
- `v0` = previous signature key during rotation window.

Customers verify by computing `HMAC(secret, t + "." + raw_body)` and constant-time comparing to `v1` (or `v0` during rotation).

### 14.3 Replay Protection

The customer SHOULD reject any webhook where `t` is more than 5 minutes old. The event `id` is unique per event; customers MUST deduplicate (NFR ID-04).

### 14.4 Delivery Semantics

At-least-once. Retried with exponential backoff up to 10 attempts over 24 hours (NFR RT-01). The HTTP response code from the customer determines retry behaviour: 2xx success, 4xx no retry (customer-side bug), 5xx and timeouts retry.

### 14.5 Event Catalog (MVP)

| Event | When |
| --- | --- |
| `user.created` | New user created |
| `user.updated` | User profile updated |
| `user.suspended` | User suspended |
| `user.deleted` | User deleted (GDPR or admin) |
| `user.login_succeeded` | User logged in |
| `user.login_failed` | Authentication failure |
| `user.mfa_enrolled` | MFA factor added |
| `user.passkey_registered` | Passkey added |
| `session.revoked` | Session revoked |
| `role.assigned` | Role assigned to user |
| `role.revoked` | Role removed |
| `application.created` | New OAuth client |
| `api_key.created` | API key minted |
| `api_key.revoked` | API key revoked |
| `subscription.updated` | Plan change |
| `security.anomaly_detected` | Anomaly detected (e.g., impossible travel) |
| `scim.user_provisioned` | SCIM user create |
| `scim.user_deprovisioned` | SCIM user deactivate |

---

### 15. OpenAPI Specification Requirements

### 15.1 Mandatory Fields per Endpoint

- `summary` — one-line description
- `description` — full description with use case
- `operationId` — stable, used by SDK generators (e.g., `users_create`, `users_list`)
- `tags` — at least one
- All parameter `schema`s
- `requestBody` schema where applicable
- All success and error `responses` with example bodies
- `security` — declaring required scopes
- `x-qeetify-rate-limit-class` — extension for rate-limit class
- `x-qeetify-idempotent` — declared as true for idempotent operations

### 15.2 Spec Validation in CI

Every PR runs:

- `openapi-spec-validator` for spec correctness.
- `spectral` with the Qeet ID ruleset (naming, response shapes, error formats) — fails build on violations.
- Contract tests that exercise every documented endpoint against the implementation.

### 15.3 Spec Publication

The aggregated OpenAPI spec for `/v1/` is published at `https://api.qeetify.com/v1/openapi.json` and `https://api.qeetify.com/v1/openapi.yaml`. Customers can pull it directly into their tooling.

---

### 16. SDK-Friendliness Considerations

### 16.1 Names

- `operationId`s generate SDK method names. Be conservative: `users_list`, `users_get`, `users_create`, `users_update`, `users_delete`. Avoid verbose names that produce ugly SDK calls.
- Parameter names match wire names: `tenant_id`, `client_id`. Some SDK languages reshape (e.g., JS camelCase) — that's the SDK's job.

### 16.2 Polymorphism

We avoid polymorphic responses (`oneOf`/`anyOf`) where possible. They produce awkward SDK code. Where unavoidable (e.g., event payloads that vary by `type`), the spec uses `discriminator` so SDKs can pick the right concrete type.

### 16.3 Pagination

SDKs offer iterator-style pagination automatically:

```python
for user in qeetify.users.list():
    print(user.email)
```

This requires the pagination shape from §9.

### 16.4 Errors as Exceptions

SDKs raise typed exceptions per error `code`:

```python
try:
    qeetify.users.create(...)
except QeetifyValidationError as e:
    for field_err in e.errors:
        print(field_err.field, field_err.message)
except QeetifyRateLimitError as e:
    time.sleep(e.retry_after)
```

The `code` in the error body drives this mapping.

### 16.5 Idempotency

SDKs surface `Idempotency-Key` as an optional argument on every applicable method. Internal retries inside the SDK automatically attach the same `Idempotency-Key` on retried attempts.

### 16.6 Streaming and Long-Running Operations

For audit log export and bulk user export, the API returns a job handle; SDKs offer `wait_until_complete()` helpers. No long-lived HTTP connections at MVP.

---

### 17. API Documentation Auto-Generation

### 17.1 Sources

- The OpenAPI spec is the source for endpoint reference docs.
- Long-form guides (tutorials, integration walkthroughs) are hand-written in Markdown and live alongside the SDK repos.

### 17.2 Tooling

- **Redoc / Stoplight / Scalar** (open decision in §19) renders the OpenAPI spec into the developer portal.
- **MDX-based guides** for tutorials.
- **Code examples** auto-generated from the SDK source — each documented endpoint has runnable examples in all six MVP SDK languages.

### 17.3 Versioned Documentation

`/docs/v1/` and `/docs/v2/` live side-by-side. The default redirects to the current major version; older versions remain accessible as long as the API version is supported.

### 17.4 Changelog

Every API change ships with a changelog entry (`https://qeetify.com/changelog`). RSS feed. Tagged by impact (`breaking`, `feature`, `fix`, `deprecation`).

### 17.5 Status Communication

`Deprecation` and `Sunset` headers (§13) drive automated `console.warn` messages in SDKs and dashboard notices for customers using deprecated endpoints.

---

### 18. Compliance & Security Considerations Specific to APIs

| # | Requirement | Source |
| --- | --- | --- |
| API-01 | All endpoints over TLS 1.2 minimum (1.3 preferred); HTTP rejected | NFR SE-01 |
| API-02 | HSTS header set on every response | NFR SE-04 |
| API-03 | CSP header set on customer-facing pages (admin dash, hosted login, portal) | NFR AS-06 |
| API-04 | Input validation on every endpoint | NFR AS-01 |
| API-05 | Output encoding context-aware | NFR AS-02 |
| API-06 | Parameterised queries only — never string concatenation | NFR AS-03 |
| API-07 | CSRF tokens on state-changing endpoints behind cookie auth (admin dash); not needed for bearer-token APIs | NFR AS-04 |
| API-08 | CORS strict — no wildcard for credentialed requests | NFR AS-05 |
| API-09 | No PII in URLs (paths or query strings) | NFR LG-04 |
| API-10 | Audit every state-changing endpoint | Compliance §9.1 |

---

### 19. Open Decisions Carried From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OQ-API-01 | Documentation renderer (Redoc vs Stoplight vs Scalar) | DevRel + Tech Writing | Phase 3 entry |
| OQ-API-02 | Webhook signing — single secret per subscription vs key versioning | Security + Backend | Phase 2 close |
| OQ-API-03 | Bulk export job pattern — synchronous (≤30 s) vs always-async with job handle | API Designer + Product | Phase 2 close |
| OQ-API-04 | Whether to support `_embed` / inlined related resources (à la Stripe `expand`) at MVP | DX + Backend | Phase 2 close |
| OQ-API-05 | GraphQL post-MVP — v2.0 introduction vs deferred | DevRel + Solution Architect | Post-MVP planning |

---

### 20. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Backend Engineering Lead |  |  |  |
| API Designer |  |  |  |
| Solution Architect |  |  |  |
| SDK Engineering Lead |  |  |  |
| Developer Relations |  |  |  |
| Security Architect |  |  |  |
| Product Manager |  |  |  |
| Technical Writer Lead |  |  |  |

---

*This document is version controlled. The API Design Standards are the single point of consistency across services and SDKs. Any deviation from these standards in a service's API requires an ADR signed by the API Designer and Backend Engineering Lead. Adding new global conventions to this document requires Solution Architect and Developer Relations review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
