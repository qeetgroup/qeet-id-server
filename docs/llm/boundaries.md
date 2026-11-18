# Boundaries — qeet-id-server

**Level:** L2 — repository · **Last verified:** 2026-11-15
**Verification scope:** ownership, inputs, outputs and security boundaries were checked against the
repository at `c2454fec`; the L1 repository map supplies the cross-repository ownership. Boundary
rules R1–R6 were checked against `depguard` in `.golangci.yml` on 2026-11-18.

What this repository owns, what it must not touch, and which changes leave it.

---

## This repository owns

| Area | Where |
|---|---|
| Every Qeet ID HTTP endpoint | `internal/bootstrap/router.go` + context handlers |
| All business logic | `internal/{access,identity,federation,developer,operations}/` |
| **All enforcement** — authn, authz, organization scope, rate limits | `internal/platform/http/httpx/`, `internal/access/authorization/` |
| Token issuance, JWKS, key rotation | `internal/platform/crypto/tokens/` |
| The database schema and every migration | `internal/platform/database/migrations/` |
| Federation protocol implementations | `internal/federation/` |
| Background workers and the outbox | `internal/platform/{worker,events}/` + `internal/bootstrap/maintenance.go` |
| **The API contract** | `api/openapi/` |
| The container image | `Dockerfile` |

## This repository does not own

Do not implement these here, and do not edit these repositories from a task scoped to this one.

| Not owned | Owner |
|---|---|
| Operator console | `qeet-id-console` |
| Hosted login UI | `qeet-id-hosted` |
| Marketing site | `qeet-id-website` |
| Qeet ID on the phone | `qeet-id-ios`, `qeet-id-android` |
| First-party SDKs and framework integrations | `qeet-id-{go,node,react,nextjs,tanstack,java,python}` |
| Product documentation | `qeet-id-docs` |
| **Terraform, Caddy, host configuration and rollout scripts** | `qeet-id-deploy` |
| PRD, TAD, product ADRs, research | `qeet-id-files` |
| Design system | `qeetrix-ui` |
| Organization standards | `qeet-context` (L0) |
| Product architecture and flows | `qeet-id-context` (L1) |

`docker-compose.yml` here is **local development dependencies only** — it is not a deployment
artifact.

---

## Inputs

| Input | Source | Required |
|---|---|---|
| HTTP requests | Console, hosted login, SDKs, mobile app, external relying parties | — |
| SAML assertions, SCIM calls, LDAP binds | Customer identity providers | per organization |
| Social OAuth callbacks | Google, GitHub, Microsoft, Apple, custom | per organization |
| Payment webhooks | Stripe, Razorpay | optional |
| Configuration | 111 environment variables | `DB_URL` plus the environment-specific requirements enforced by `Config.Validate()` |
| Persistent state | PostgreSQL | **required** |

## Outputs

| Output | Consumer |
|---|---|
| REST API responses | Console, login, SDKs, mobile, customer applications |
| **JWTs and JWKS** | **Every Qeet product** and every external relying party |
| OIDC discovery document | Relying parties |
| SAML assertions | Customer service providers |
| SCIM responses | Customer identity providers |
| Signed webhooks | Customer endpoints |
| Domain events | NATS subscribers (optional) |
| Metrics, traces, logs | Observability backends |

## Contracts this repository publishes

| Contract | Location | Consumers who cannot be surveyed |
|---|---|---|
| REST API | `api/openapi/` (5 documents) | external customers |
| OIDC / OAuth | `internal/federation/oidc/` | **every Qeet product**, external RPs |
| SAML | `internal/federation/saml/` | customer IdPs and SPs |
| SCIM 2.0 | `internal/federation/scim/` | customer IdPs |
| Webhooks | `internal/developer/webhook/` | customer endpoints |
| Database schema | `internal/platform/database/migrations/` | this repository only |

**The four marked contracts have consumers outside Qeet's control.** Treat every change to them as
breaking until proven otherwise: additive only, or a deprecation window.

---

## Enforced internal boundaries

Two rules, enforced by `depguard` in `.golangci.yml`:

```text
cmd/*                  entrypoints
   ↓
internal/bootstrap     composition root — wires everything
   ↓
internal/<context>     business logic          R2: must not import cmd/* or bootstrap
   ↓
internal/platform      pure infrastructure     R1: must not import a context, cmd/*, or bootstrap
```

**Not enforced:** cross-context imports. The five bounded contexts can import each other today.
Depend on interfaces (declared once beside their implementation, or in the consumer when no shared
one fits) so the extraction seam survives.

## Security boundaries

**The trust boundary is this repository.** Everything outside it is untrusted input, including
Qeet's own consoles.

| Boundary | Enforcement |
|---|---|
| Unauthenticated → authenticated | `httpx.RequireAuth` |
| **Organization A → organization B** | `httpx.EnforceOrganizationScope` + `WHERE organization_id = $1`, backed by row-level security on organization-owned tables in organization-administration requests (`scopeOrganizationRoutes`) |
| Caller → permission | `rbac.Enforce` with `internal/bootstrap/permissions.go` |
| Browser → API | CORS allowlist, then CSRF double-submit |
| Process → secrets | Managed store; `Config.Validate()` boot gate |
| External protocol input | SAML, SCIM, LDAP parsers — highest-risk surface |

**A UI permission check is not a security boundary.** The console hides buttons; this repository
decides. If hiding a button is the only thing preventing an action, that is a defect here.

---

## Safe to modify without cross-repository coordination

- Internal refactoring behind an unchanged contract
- Adding a test
- A bug fix that does not change the contract
- An **additive** migration
- Logging, metrics and tracing detail
- Performance work
- Adding an **optional** response field — consumers ignore unknown fields
- Internal dependency updates

## Requires cross-repository coordination

For *what review* a change needs, see the safe change matrix in [context.md](context.md#safe-change-matrix).
For product-level fan-out, consult `qeet-id-context/CHANGE-MATRIX.md`. Before starting any of these:

| Change | Reaches |
|---|---|
| **JWT claims** | Console, login, all SDKs, **every Qeet product**, external RPs |
| **Signing key / JWKS rotation** | Every token verifier everywhere |
| **OIDC discovery document** | SDKs, all relying parties |
| **SCIM schema or endpoint** | Customer IdPs — external, unsurveyable |
| **SAML metadata or certificate** | Customer IdPs and SPs — external |
| **Webhook payload or signature** | Customer endpoints — fails silently |
| New or changed endpoint | OpenAPI, SDKs, console, login, docs |
| New permission | Console, SDKs |
| Error code or envelope | Console, login, SDKs |
| Cookie name, flags or scope | Console, login, React SDK |
| Hostname | Deploy, CORS, redirect URIs, **WebAuthn origins**, SDK defaults |

## Cross-repository relationships

```text
qeet-context (L0)  →  qeet-id-context (L1)  →  qeet-id-server (this repository)
                                                      │  publishes the API contract
        ┌──────────────┬──────────────┬───────────────┼──────────────┬──────────────┐
        ▼              ▼              ▼               ▼              ▼              ▼
  qeet-id-console  qeet-id-hosted  ios/android      SDKs          qeet-id-docs   external
   (BFF, bearer)    (cookie+CSRF)  (device token)  (server/browser)  (manual)    consumers

  qeet-id-deploy  ──provisions──►  this repository
  qeet-id-files   ──specifies───►  this repository   (intent, not implementation)
```

**This repository depends on no other Qeet product.** It is the root of the identity graph — every
other Qeet product authenticates against it. A dependency back into a relying party would be an
unbootstrappable cycle.

## Hard limits — never do these here

1. **Never take organization scope from request input.** Use `httpx.RequireOrganization`.
2. **Never edit an applied migration.** Add a pair.
3. **Never hand-edit `dbgen/`.** Change `queries.sql` and regenerate.
4. **Never wire dependencies outside `internal/bootstrap`.**
5. **Never make `internal/platform` import a bounded context.** CI fails.
6. **Never add a route without updating `api/openapi/`.** The local test gate fails. Edit
   `api/openapi/src/` and run `make openapi`; the five documents themselves are generated.
7. **Never weaken a security control to make a test pass.**
8. **Never commit a real secret** — `.env.example` holds placeholders only.
9. **Never flatten the chi route tree** — the organization guard fails open silently.
10. **Never change another repository** from a task scoped to this one.
