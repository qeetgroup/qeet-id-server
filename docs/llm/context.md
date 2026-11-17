# Repository Context — qeet-id-server

**Level:** L2 — repository · **Status:** active · **Evidence state:** verified
**Last verified:** 2026-11-15
**Verification scope:** package structure, dependency rules, router and route-policy wiring,
authentication and authorization enforcement, tenant row security, migrations, configuration,
workers, OpenAPI coverage and test layout were checked against `c2454fec`. Focused bootstrap,
HTTP-security, token and authorization tests passed. Live providers, deployed infrastructure and
production state were not checked. Claims about the *product* are inherited from L1.

---

## Repository identity

`qeet-id-server` is the **Go backend of Qeet ID**. It is a modular monolith: one Go module, one
PostgreSQL database and five bounded contexts. The API is the primary deployable; worker and
scheduler entry points can run its asynchronous work independently.

| | |
|---|---|
| Module | `github.com/qeetgroup/qeet-id-server` |
| Language | Go 1.27.0 (toolchain 1.27.4) |
| Router | chi v5 |
| Database | PostgreSQL, pgx v5, hand-written SQL via sqlc |
| Binaries | `api`, `worker`, `scheduler`, `migrate`, `seed` |
| Port | 4001 |
| Status | active repository; the **product** is pre-1.0 |

## Relationship to the Qeet context layers

```text
qeet-context      L0   organization standards
      ↓
qeet-id-context   L1   Qeet ID product architecture
      ↓
qeet-id-server    L2   THIS DOCUMENT — implementation
      ↓
source                 L3/L4
```

**This document does not restate L0 or L1.** It describes how this repository implements what they
require.

| Question | Level |
|---|---|
| What is Qeet's cookie policy? Domain model? API standard? | **L0** — `qeet-context` |
| What is Qeet ID? Which repositories? How does the auth *flow* work? | **L1** — `qeet-id-context` |
| Where is that flow implemented? Which package? How is it wired? | **L2** — here |
| What exactly does this function do? | **L3/L4** — the source |

**Policy flows down and is not overridden here.** If this implementation does not meet an L0 or L1
requirement, that is a product-level divergence to record in `qeet-id-context` and its
`CONTEXT-CHANGELOG.md` — not a redefinition of the standard.

---

## Responsibilities

This repository owns:

- **The HTTP API** — every endpoint Qeet ID exposes
- **All business logic** across five bounded contexts
- **All enforcement** — authentication, authorization, tenant isolation, rate limiting
- **Token issuance and verification** — JWT signing, JWKS, key rotation
- **Identity persistence** — the schema, the migrations, the queries
- **Federation protocol implementation** — OIDC provider, SAML SP and IdP, SCIM, LDAP, social
- **Machine and agent identity** — API keys, service principals, agents
- **Background work** — outbox dispatch, webhooks, retention, GDPR, SIEM, anomaly detection
- **The API contract** — `api/openapi/`, five OpenAPI 3.1 documents

## Non-responsibilities

Owned elsewhere. Do not implement these here:

| Not owned | Owner |
|---|---|
| Operator console UI | `qeet-id-console` |
| Hosted login UI | `qeet-id-hosted` |
| Marketing site | `qeet-id-website` |
| Qeet ID on the phone | `qeet-id-ios`, `qeet-id-android` |
| Client SDKs | `qeet-id-{go,node,react,nextjs,tanstack,java,python}` |
| Product documentation | `qeet-id-docs` |
| **Deployment manifests, Terraform, rollout** | `qeet-id-deploy` |
| Requirements, PRD, TAD, product ADRs | `qeet-id-files` |
| Design system | `qeetrix-ui` |

---

## Runtime architecture

```text
HTTP request
   ↓  chi router                internal/bootstrap/router.go
   ↓  global middleware         RequestID · RealIP · Recoverer · InFlight
   ↓                            SecurityHeaders · AccessLog · tracing · metrics
   ↓                            CORS  →  CSRF
   ↓
   ├─ root routes               /healthz · /readyz · /metrics
   ├─ protocol mounts           OIDC · SCIM · SAML · LDAP  (fixed spec locations)
   │
   └─ /v1
        ├─ public group         rate-limited; no session required
        └─ authenticated group
               ↓  API-key middleware
               ↓  LoginSessionAuth       qe_ls cookie, on LoginSessionRoutes() only (no Authorization header)
               ↓  RequireAuth            verify JWT: kid, signature, expiry; the session not ended → principal
               ↓  EnforceTenantScope     {tenantID} must equal the caller's tenant
               ↓  rate limiters          per tenant · per user · per API key
               ↓  rbac.Enforce           route permission from permissions.go
               ↓
            handler  →  domain logic  →  sqlc query  →  PostgreSQL
            (these are LAYERS, not filenames — see Package architecture)
                                        ↓
                                    outbox (same transaction)
                                        ↓
                                 worker → webhook / NATS
```

**Status:** verified · **Evidence:** `internal/bootstrap/router.go`

**Ordering is load-bearing.** CORS runs before CSRF. Tenant scope is checked *before* permissions, so
a caller can never reach a permission check for another tenant's resource.

## HTTP architecture

**Status:** verified · **Evidence:** `internal/bootstrap/router.go`, `internal/platform/http/`

| Concern | Where |
|---|---|
| Router | chi v5, built in `NewRouter()` — `internal/bootstrap/router.go` |
| Global middleware | `RequestID` · `RealIP` · `Recoverer` · `InFlight` · `SecurityHeaders` · `AccessLog` · tracing · metrics · CORS · CSRF |
| Root routes | `/healthz` · `/readyz` · `/metrics` |
| Protocol mounts | `MountPublic` for OIDC, SCIM, SAML, LDAP — fixed spec locations at the root |
| `/v1` public group | rate-limited, no session — invites, social, billing webhooks, agent token, passkey login, admin portal, OAuth authorize/token-code |
| `/v1` authenticated group | API key → hosted-login session (only the few `LoginSessionRoutes()` the hosted login calls) → `RequireAuth` → `EnforceTenantScope` → rate limits → `rbac.Enforce` |
| Error taxonomy | `internal/platform/http/errs/` — ~50 domain files, stable machine codes |
| Status mapping | `internal/platform/http/httpx/error_status_*.go` — 1:1 mirror of `errs/` |
| Cursor pagination | `internal/platform/http/paging/` |
| Request helpers, principal, guards | `internal/platform/http/httpx/` |

**Adding a route means choosing a group.** The public group opts out of authentication, tenant scope,
rate limiting and RBAC entirely. Use it only for genuinely unauthenticated endpoints.

**A new error domain needs a file in both** `errs/` and `httpx/error_status_*.go` — the pairing is
1:1 by domain.

## Package architecture

```text
cmd/*                  thin entrypoints — call into bootstrap
   ↓
internal/bootstrap     composition root — the ONLY package that wires
   ↓
internal/<context>     five bounded contexts — business logic
   ↓
internal/platform      shared kernel — pure infrastructure
```

| Package | Responsibility |
|---|---|
| `internal/access` | Authentication, authorization (RBAC/ABAC/ReBAC/AuthZEN), MFA, passkeys, recovery, risk, threat |
| `internal/identity` | Tenants, users, groups, invitations, verification, domain verification, branding |
| `internal/federation` | OIDC provider, SAML (SP + IdP), SCIM, LDAP, social, admin portal |
| `internal/developer` | API keys, service principals, agents, auth hooks, webhooks, secrets vault, token vault, VCs |
| `internal/operations` | Audit, analytics, billing, GDPR, retention, SIEM, notifications, entitlements, search, AI assistant |
| `internal/platform` | HTTP, database, crypto, cache, config, events, workers, messaging, observability |
| `internal/bootstrap` | Composition root: dependencies, router, permission map, lifecycle, server |

110 packages under `internal/` and `cmd/` contain hand-written Go files, 163 with the
sqlc-generated `dbgen` packages.

**File-naming convention — `<domain>.go`, not layered file names.** Domain logic, persistence and
HTTP handlers usually live in **one file named after the package**; additional files split by
**feature**, not by layer. Only four packages use `service.go`/`repository.go` naming and 17 domain
packages have a dedicated `http.go` (the platform database-test helper is the eighteenth).

```text
access/passkeys/     passkey.go                          ← everything in one file
developer/agents/    agent.go                            ← everything in one file
access/mfa/          mfa.go  totp.go  otp.go  push.go    ← split by FEATURE
federation/oidc/     oidc.go  token.go  authorize.go  device.go  ciba.go
identity/users/      domain.go  http.go  repository.go   ← one of the four layered packages
```

**Do not assume a `service.go` or `repository.go` exists** — check
[subsystems.md](subsystems.md) first.

Every leaf package additionally carries `queries.sql` + `sqlc.yaml` + a generated `dbgen/`
(`db.go`, `models.go`, `queries.sql.go`), which is sqlc output and is never hand-edited.

## Dependency rules

**Status:** enforced by `depguard` in `.golangci.yml` (lint fails on a violation)

```text
cmd/*  →  internal/bootstrap  →  internal/<context>  →  internal/platform
```

**Two rules are enforced by `depguard` in lint; hosted Verify and local `make ci` both run lint:**

- **R1** — `internal/platform/*` imports **no** bounded context, **no** `cmd/*`, and **not**
  `internal/bootstrap`. Platform stays pure infrastructure.
- **R2** — a bounded context imports **neither** `cmd/*` **nor** `internal/bootstrap`. Business logic
  sits below wiring and entrypoints.

### Cross-context imports are NOT enforced — and are widespread

The test states it verbatim: *"Cross-context imports are not yet enforced."* The actual shape, from
the import graph — **38 import statements across 8 pairs**:

```text
operations/audit       ← access(9) · federation(8) · identity(5) · developer(5)
access/authentication  ← federation(6) · identity(2)
identity/users         ← federation(2) · access(1)
```

- **`operations/audit` is a de-facto shared kernel** — every other bounded context imports it, because
  audit writes join the caller's transaction.
- `access ↔ identity` is bidirectional at package granularity without forming a Go import cycle.
- **Nothing imports `developer`.** It is a leaf.

Treat this as an unguarded seam, not permission. Prefer interfaces declared by the consumer over
importing another context's concrete types, so the extraction seam survives.

### Platform dependencies per context

Universal baseline: `platform/http/errs` + `platform/http/httpx`. Distinctive:
`identity` is the only `http/paging` consumer · `operations` is the sole `platform/ai` consumer and
uses `pgxpool` directly rather than the `database` helpers · **`access` does not import
`cache/ratelimit`** — rate limiting lives in `httpx` middleware and `operations/ratelimits`.

## Composition root

`internal/bootstrap` is the only package that wires anything.

| File | Role |
|---|---|
| `app.go` | Application assembly |
| `dependencies.go` | Constructs every service and repository |
| `keys.go` · `mail.go` · `infra.go` · `sso.go` · `adapters.go` | Its building blocks: vault and signing keys; the message chain; outbound policy, NATS, rate limits and the validator; SAML and platform social sign-in; cross-context adapters |
| `router.go` | Builds the chi router, registers middleware, mounts every route |
| `permissions.go` | Route → required-permission map consumed by `rbac.Enforce` |
| `server.go` | HTTP server |
| `lifecycle.go` | Startup and graceful shutdown |

**A new service, route, middleware or worker is wired here.** A package that wires itself has
violated the pattern and will usually break R1 or R2.

## Entrypoints

| Binary | Purpose | Notes |
|---|---|---|
| `cmd/api` | HTTP API server | Body is `bootstrap.Run()`. Workers run embedded by default |
| `cmd/worker` | Background workers standalone | Run to scale workers independently of API replicas |
| `cmd/scheduler` | Scheduled maintenance, standalone (the API also runs it embedded) | Each job claimed in `platform.scheduled_job_runs` — once per interval across instances |
| `cmd/migrate` | golang-migrate wrapper | Structured exit codes for init containers |
| `cmd/seed` | Demo data | **A workstation and the kit's DEV only** (`SERVICE_ENV=dev`, or `local` with profile `dev`). Drives real services, so hashes and audit chains are real |

---

## Configuration

**Evidence:** `internal/platform/config/config.go` — a single struct with **138 `envconfig` tags**.

`DB_URL` is required to connect. Many fields have development defaults or gate optional
capabilities, but a non-development process has additional mandatory combinations enforced by
`Config.Validate()`: secure JWT signing and retirement settings, a secrets provider and its key
material, an email provider, explicit CORS origins, safe public URLs, and environment-specific host
rules. The fields cover service, database, tokens, crypto/KMS, HTTP/CORS/CSRF, URLs, WebAuthn,
social providers, email, push, SMS, Redis/NATS, billing, password hygiene, observability, and AI.

`.env.example` documents every variable with **placeholders only**. `.env` and `.secrets/` exist
locally, are gitignored, and must never be read into a committed file.

### The boot gate

`SERVICE_ENV` is an explicit enum — `dev`, `local`, `prod` — and `config.Load()` rejects any other
value, so the gate below is switched on deliberately rather than by "anything that is not `dev`".
`local` is a Local-tier runtime of the Qeet ID Kit (`qeet-id-kit`) — the DEV, TEST (QA testing) and
STAGING (UAT testing) environments, selected by `SERVICE_PROFILE=dev|test|staging`: every production gate applies, and `APP_BASE_URL`/`LOGIN_BASE_URL` must be
`localhost` or `*.localhost`. `prod` additionally rejects `*.localhost`. Code asks `cfg.IsDev()`
instead of comparing strings.

`Config.Validate()` **refuses to start** outside `SERVICE_ENV=dev` if any insecure setting is
present — CSRF disabled, dev trust headers on, wildcard CORS origins, empty signing key. This is a
control, not a convenience. Do not add an escape hatch.

Four variables are security-critical: `CSRF_COOKIE_DOMAIN` (must be the product zone, never
`.qeet.in`), `ALLOWED_ORIGINS`, `CSRF_DISABLED`, `AUTH_DEV_TRUST_HEADERS`.

## Database

One PostgreSQL database, **seven schemas**: `auth`, `tenant`, `account`, `rbac`, `audit`, `platform`,
`qeetai`.

- **Driver:** pgx v5. **Queries:** hand-written SQL in `queries.sql`, compiled by **sqlc** into
  `dbgen/` packages. 53 `queries.sql`/`sqlc.yaml` pairs and 53 `dbgen` directories.
- **Generated `dbgen/` code is never hand-edited.** Change `queries.sql` and regenerate.
- Transactions are opened at the service layer, so a domain write and its outbox row commit together.

### Migrations

**Evidence:** `internal/platform/database/migrations/` — 12 up/down pairs, `0001`–`0012`: the schema
baseline, one file per schema with every table in its final shape (`0001` schemas and the
application role, `0002` functions, `0003`–`0009` the schemas, `0010` foreign keys between schemas,
`0011` row-level security, `0012` owner guards and triggers). Embedded with `//go:embed *.sql` in
`runner.go` and applied on startup.

```text
NNNN_description.up.sql
NNNN_description.down.sql
```

**Never edit an applied migration.** Add a new pair. Expand → migrate → contract across releases; a
migration that drops or renames ships at least one release after the code that stopped using it.

## Tenant isolation

**The most security-critical mechanism in this repository. Read all of it.**

```text
authenticated principal        (JWT or API key)
        ↓
httpx.RequireTenant(r)         the ONLY trustworthy source of tenant scope
        ↓
httpx.EnforceTenantScope       {tenantID} path param must equal the caller's tenant → else 403
        ↓
service
        ↓
repository query               WHERE tenant_id = $1
```

**Evidence:** `internal/platform/http/httpx/auth.go`, `internal/bootstrap/router.go`

The source states the rule directly:

> *"RequireTenant returns the principal's tenant id — the only trustworthy source of tenant scope.
> Handlers must never take tenant id from URL/body."*

### Membership

A person belongs to an organisation when it is their account's home (`account.users.tenant_id`) or
they hold one of its roles (`rbac.user_roles`). Every membership check — signing in to its
applications, renewing, switching organisation, the member list — uses this rule; permissions still
come only from roles, so a home account with none has no access. A guest leaves when their roles are
removed; a home account is suspended or deleted instead.

### Row-level security is the second layer

Migration 0160 puts a `tenant_isolation` policy on each organisation-owned table: a connection sees
and writes only the rows of the organisation set on it (`qeet.tenant_id`), and every row when none
is set. Connections run as `qeet_app` (`postgres.NewPool`); `httpx.ScopeDatabase` sets the caller's
organisation through the context, applied each time a connection leaves the pool. The router
applies it to the organisation-administration routes — those whose policy needs a permission or a
machine scope (`scopeOrganisationRoutes`); a person's own routes act across their organisations.

| Where | A missing `tenant_id` predicate causes |
|---|---|
| Organisation-administration request, organisation-owned table | nothing — the database hides the other organisations' rows |
| A person's own route, background job, sign-in, public flow, account-level table | **cross-tenant data exposure** |

The account-level tables (`accountLevelTables` in `migrations/schema_db_test.go`: a person's
sessions, memberships, invitations inbox and such) have no policy. Requests that act across
organisations by design — switching organisation, creating one, a person's own invitations, export
and account deletion — call `postgres.AcrossTenants`. The owner-guard trigger functions run as their
owner, so they always see every organisation.

### Restructuring routes is a security change

`internal/bootstrap/router.go` warns that the guard depends on chi's nested-route matching:
flattening the routes onto the top mux makes it **silently fail open**. `rbac` and `users` also
self-scope in-handler; other tenant-scoped resources rely entirely on the middleware.

## Authentication

**Status:** verified
**Evidence:** `internal/platform/crypto/password/hasher.go`, `internal/access/authentication/`

Password hashing is **Argon2id** (`m=19456,t=2,p=1`) with transparent upgrade of legacy bcrypt on
successful login; MFA recovery codes use it too. Machine secrets — API keys and service-principal,
agent and OAuth client secrets — are random (≥192 bits), so they are stored as their SHA-256
(`sha256$…`, `password.HashSecret`): Argon2id adds nothing to such a secret and would cost a
sign-in's CPU on every call. An older Argon2id hash verifies once and is replaced.

Implemented mechanisms: password · passkeys (WebAuthn) · magic link · email and SMS OTP · TOTP ·
push approval · social login · adaptive risk (**off by default**) · sign-in lockout ·
breached-password check (env-gated).

Password sign-in lockout (`authentication/lockout.go`) counts failures per account + source network
(the client IP from `httpx.ClientIP`; IPv4 address or IPv6 /64) — the lock a tenant configures in its
authentication policy within the `LOGIN_LOCKOUT_*` bounds — plus a looser per-account cap and a
per-source counter across accounts (spraying). Unknown addresses are counted and timed like real
ones. Whose settings apply: the tenant of the OAuth client a hosted sign-in names
(`auth.Service.SignInTenant`), else the platform defaults — never the account's own tenant before the
password is verified. If its counters cannot be read or written the sign-in **fails closed** (503
`auth.sign_in_unavailable`, counted in `sign_in_lockout_unavailable_total`). Locks and throttled
sources reach the Threats → Anomalies store (`credential_stuffing`, `password_spraying`).

Every path that sets or replaces a password (sign-up, hosted registration, self-service change,
reset, invite accept, admin create / set-password, bulk import) runs one check,
`authpolicy.Service.ValidateForTenant`: the rules of the organisation the account belongs to (the
platform baseline `DefaultPolicy`, 8 characters, for a tenant-less account), the offline strength
baseline, then the breach check — fail-open, each allowed-on-error counted in
`breached_password_check_allowed_on_error_total`. Services reach it through consumer-declared
interfaces and refuse (501) to set a password when it is not wired.

**Per-package file pointers: [subsystems.md](subsystems.md#access--authentication).**
For the product-level flow narrative, read `qeet-id-context/FLOWS/`.

## Authorization

| Model | Package |
|---|---|
| RBAC + route enforcement | `internal/access/authorization/rbac/` |
| ABAC — deny-overrides, fail-closed | `internal/access/authorization/abac/` |
| ReBAC — Zanzibar relation tuples | `internal/access/authorization/rebac/` |
| AuthZEN PDP/PEP | `internal/access/authorization/authzen/` |
| Composed decision — every check and the route guard ask it | `internal/access/authorization/decide/` |
| Tenant policy / password rules | `internal/access/authorization/{policy,authpolicy}/` |

The **route → permission map** lives in `internal/bootstrap/permissions.go` and is consumed by
`rbac.Enforce` as router middleware.

Every authenticated route has a `RoutePolicy` and an unlisted route is denied. A user needs the
policy's role permission. API keys, service principals and agents are checked by actor type and need
one of its machine scopes, unless the policy explicitly leaves a resource-derived scope check to the
handler. A token issued to an application needs both its user's permission and the route's approved
OAuth scope. ABAC denies are evaluated by the composed checker and override a role grant.

## Tokens and cryptography

| Concern | Implementation |
|---|---|
| Algorithm | **ES256 or RS256**, by the active key's type (EC P-256 or RSA of 2048 bits or more). `validMethods` allows only those two and `keyFunc` holds each key to its own, so `alg` confusion is impossible |
| `kid` | RFC 7638 JWK thumbprint, computed at key load |
| Verification | Missing or unknown `kid` → rejected |
| Rotation | Shared encrypted registry: candidate staging, explicit activation, replica refresh, timed public-key retirement |
| Password hash | Argon2id |
| CSRF token | HMAC-keyed, constant-time comparison |
| Vault | AES-256-GCM, per-tenant HKDF-derived key, static or AWS KMS provider |
| Randomness | `crypto/rand` only |

**Evidence:** `internal/platform/crypto/tokens/{jwt,registry}.go`, `internal/platform/crypto/envelope/`

> There is no signing-key mutation API. `JWT_SIGNING_KEY` stages encrypted key
> material in PostgreSQL; `JWT_ACTIVATE_SIGNING_KEY=true` performs the explicit
> activation step. The executable wiring is in `internal/bootstrap/keys.go`; registry and retirement
> behavior live in `internal/platform/crypto/tokens/registry.go`.

## Federation

**Status:** verified · **Evidence:** `internal/federation/`, `internal/bootstrap/router.go`

Qeet ID is both a **service provider** (consuming a customer IdP over SAML, LDAP or social) and an
**identity provider** (OIDC, and SAML IdP for customer SPs).

Protocol endpoints are mounted at the **root, not under `/v1`**, because the specifications require
fixed locations — `.well-known/*`, `/scim/v2`, `/saml/*`, `/ldap/*`. `/oauth/introspect` and
`/oauth/revoke` also sit at the root. The discovery and RFC 8414 authorization-server metadata
documents advertise the actual endpoints; protected-resource metadata is served for OAuth/MCP
discovery.

**SAML, SCIM and LDAP parse untrusted external input** — the highest-risk surface in this repository.

**Per-package file pointers: [subsystems.md](subsystems.md#federation).**

## Developer, machine and agent identity

**Status:** verified · **Evidence:** `internal/developer/`

Three non-human identity forms: **API keys** (`qk_`, `<prefix>.<secret>`, the secret stored as its
SHA-256), **service principals** (`client_credentials`, short-lived service JWT scoped to one tenant),
and **AI agents** (`actor_type="agent"`, tokens **re-minted rather than refreshed**, with a sponsor
and a kill switch).

Also here: auth hooks (**default fail-open**, ADR-0011), webhooks with dead-letter, the AES-256-GCM
secrets vault with per-tenant HKDF keys, the third-party token vault, and W3C JWT-VCs.

**No bounded context imports `developer`** — it is a leaf.

**Per-package file pointers: [subsystems.md](subsystems.md#developer).**

## Events and workers

```text
service transaction
   ↓  business row + outbox row committed TOGETHER
platform.outbox
   ↓  dispatcher (worker)
webhook delivery  /  NATS publish
   ↓  exhausted
dead-letter
```

The dispatcher hands every committed event to `webhook.Relay`, which queues the events named in
the catalogue (`webhook.Events`, `internal/developer/webhooks/events.go`) for the subscriptions of
the organisation the payload's `tenant_id` names, then publishes it to NATS. A subscription may name
only catalogue events, so an outbox event a customer should receive needs a catalogue entry and a
`tenant_id` in its payload. An event's name is its version: change a payload incompatibly under a new name.

**Evidence:** `internal/platform/events/outbox/`, `internal/platform/worker/worker.go`

Workers run **embedded in `cmd/api` by default**; set `EMBEDDED_WORKERS=false` when `cmd/worker`
runs them standalone. Webhook, outbox, and GDPR queues use durable PostgreSQL leases with
owner-conditional finalization; retries retain stable event/delivery IDs. Registered workers, one
list in `bootstrap/dependencies.go` that both binaries run: signing-key refresh, outbox dispatch,
OIDC back-channel logout, webhooks, GDPR, retention, SIEM, audit anomaly, scheduler.

Scheduled maintenance (audit-chain verification of every organisation, session, MFA, sign-in
history, published-outbox and dead-letter cleanup) is `bootstrap.MaintenanceJobs`, run by `worker.RunScheduled`: the
API runs it as its embedded `scheduler` worker, and `cmd/scheduler` or `cmd/worker` can run it
standalone. Each job is claimed in `platform.scheduled_job_runs` before it runs, so it runs once per
interval however many instances run it, each in its own goroutine (at most four at once); each
verification is stored in `platform.audit_verification_runs`. Verification goes on from each chain's
checkpoint (`platform.audit_chain_checkpoints`) and walks every chain from its first row once a week;
deleting a chain's checkpoint makes the next run walk it from the start.

**Choose async when** the work is retryable, slow, or must survive a request; **sync when** the
caller needs the result or the operation must be atomic with the response.

## Observability

| Signal | Implementation |
|---|---|
| Logs | Structured — `internal/platform/observability/logging/` |
| Metrics | Prometheus at `/metrics` — `.../metrics/` |
| Traces | OpenTelemetry — `.../tracing/`, `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Health | `/healthz` liveness, `/readyz` readiness — `.../health/` |
| Correlation | `X-Request-Id` via chi `RequestID` middleware, echoed into errors |
| Audit | Hash-chained — `internal/operations/audit/` |

**Never log** credentials, tokens, personal data, or another tenant's identifiers.

## API contracts

`api/openapi/` — **five OpenAPI 3.1 documents**, split by bounded context, `info.version 0.2.0`.
There is deliberately no monolithic spec. The documents are generated from `api/openapi/src/` (one
file per path, shared definitions in `src/shared/`) by `make openapi` (Redocly CLI, pinned in
`src/bun.lock`) and committed; `make openapi-check` fails when one is stale.

**The coverage gate is the important part:** `internal/bootstrap/openapi_coverage_test.go` fails the build if
any mounted route is undocumented. A route cannot silently appear.

**A route change and its spec change belong in the same commit.**

Every document lists `https://api.id.qeet.in` first and `http://localhost:4001` second. Runtime OIDC
metadata derives public protocol URLs from the validated public base URL rather than trusting a
request host in production.

## Testing

| Suite | Path | Runs |
|---|---|---|
| Unit | alongside source | `go test ./...` |
| **OpenAPI coverage gate** | `internal/bootstrap/openapi_coverage_test.go` | with unit tests |
| OpenAPI validity and consistency | `internal/bootstrap/openapi_valid_test.go`, `openapi_consistency_test.go` | with unit tests |

Tests are **colocated** (`_test.go` beside the source). The current tree has 330 Go test files and
1,289 `Test*` functions; 169 files are integration-tagged and run through the database test gate.
Counts are orientation only—package and behavior coverage matter more than totals.

**Coverage gaps worth knowing before you change these:**

| Package | Unit tests |
|---|---|
| `operations/notifications` | no direct package test; exercised through wider flows |
| Protocol and lifecycle paths | several depend on integration-tagged database tests in addition to direct unit tests |

`internal/bootstrap/permissions_test.go` walks the exact authenticated production mounts and
requires an explicit route policy. `internal/bootstrap/openapi_coverage_test.go` walks all three
production mount helpers and compares them bidirectionally with the union of the five OpenAPI
documents, including API-auth security classification.

## CI/CD

| Job | What it runs |
|---|---|
| `verify` (`ci.yml`) | On pull requests into `develop` and `main`: `go build ./...` · `go vet ./...` · `golangci-lint` v2.15.0 · `govulncheck ./cmd/... ./internal/...` · API contract (`make openapi-check`, the OpenAPI tests) · gitleaks |
| `image` (`candidate.yml`) | On push to `release/**` or `hotfix/**`: the test image `ghcr.io/qeetgroup/qeet-id-server:sha-<commit>` |
| `deploy` (`deploy.yml`) | A merged release or hotfix into `main`: that tested image to ECR, roll the host via GitHub OIDC, then tag |
| local (`make ci`) | `go test -race` with the database tests · `sqlc diff` · `gosec` (`#nosec` needs a rule and a reason) |

`.golangci.yml` enables `errcheck`, `govet`, `staticcheck`, `misspell`, `unused`, `ineffassign`,
`errorlint`, `nilerr`, `bodyclose`, `sqlclosecheck`, `rowserrcheck`, `nolintlint`, `forbidigo` and
`depguard` (R1/R2), plus `gofmt`/`goimports`; `dbgen` packages are excluded. `make lint` runs the
same lint as CI.

## Deployment

**This repository owns the release-triggered image promotion workflow, but not the infrastructure it
targets.**

- `Dockerfile` — build on `golang:1.27.4-alpine` (same Go as go.mod's toolchain), ship on `gcr.io/distroless/static-debian13:nonroot`,
  non-root user, `EXPOSE 4001`.
- `docker-compose.yml` — **local dependencies only**: postgres :5001, nats :4222, mailpit :8025.
- Terraform, Caddy, production host configuration and rollout scripts live in **`qeet-id-deploy`**.
- `.github/workflows/candidate.yml` builds the image testers run, on push to `release/YEAR.MONTH.0`
  or `hotfix/YEAR.MONTH.N`; `.github/workflows/deploy.yml` promotes that same image to AWS when the
  branch merges into `main`.

The workflow files encode triggers and credentials, not the human authority to cut or approve a
release. Read the current Jira release issue, environment protection and repository settings for
that approval; this repository alone cannot establish who authorized production.

Migrations apply on startup, so a deploy is also a migration.

## Development workflow

```bash
make install          # go mod download
make db-up            # postgres :5001, nats :4222, mailpit :8025
make dev-secrets      # local JWT + SAML keys into .secrets/
make migrate-up       # one migration
make seed             # demo data
make dev              # API on :4001
```

Then `make test`, `make lint`, `make build`.
**Do not invent Make targets** — the list in `AGENTS.md` is complete.

## Security-critical areas

**Status:** verified · **Evidence:** each path below exists and was read

| Area | Source path | Risk | Review expectation |
|---|---|---|---|
| **Tenant isolation** | `internal/platform/http/httpx/auth.go` | **Critical** | Security review, mandatory |
| **Route tree / middleware order** | `internal/bootstrap/router.go` | **Critical** | Security review — the tenant guard depends on nesting |
| **Route permissions** | `internal/bootstrap/permissions.go` | **Critical** | Security review · executable route-policy coverage |
| **Authorization** | `internal/access/authorization/` | **Critical** | Security review |
| **Authentication, sessions** | `internal/access/authentication/` | **Critical** | Security review |
| **Tokens, signing, rotation** | `internal/platform/crypto/tokens/jwt.go` | **Critical** | Security review · cross-repo |
| **Hashing, vault crypto** | `internal/platform/crypto/{password,envelope}/` | **Critical** | Security review |
| **CSRF** | `internal/platform/http/httpx/csrf.go` | **Critical** | Security review |
| **Boot gate** | `internal/platform/config/config.go` | **Critical** | Security review |
| MFA, passkeys, recovery | `internal/access/{mfa,passkeys,recovery}/` | High | Security review |
| Federation parsers | `internal/federation/{saml,scim,ldap}/` | High | Security review — untrusted external input |
| Machine & agent identity | `internal/developer/{api-keys,principal,agents,credentials}/` | High | Security review |
| Webhooks | `internal/developer/webhooks/` | High | Security review — external consumers |
| Audit hash chain | `internal/operations/audit/` | High | Security review |
| Migrations | `internal/platform/database/migrations/` | High | Data review |
| Risk & threat | `internal/access/{threat,risk}/` | Medium | Review |

## Safe change matrix

What review a change needs. Cross-repository impact is expanded in
[boundaries.md](boundaries.md#requires-cross-repository-coordination) and, at product level, in
`qeet-id-context/CHANGE-MATRIX.md`.

| Change | Security review | API review | DB / migration | Cross-repo review |
|---|:--:|:--:|:--:|:--:|
| Internal refactor | maybe | no | no | usually no |
| Observability-only change | usually no | no | no | usually no |
| Adding a test | no | no | no | no |
| New endpoint | maybe | **yes** | maybe | **yes** |
| New permission | **yes** | yes | no | **yes** |
| Authentication change | **yes** | yes | maybe | **yes** |
| Authorization change | **yes** | yes | maybe | **yes** |
| **Tenant isolation change** | **mandatory** | maybe | maybe | **yes** |
| **Route tree restructure** | **mandatory** | no | no | no |
| Schema change | yes | maybe | **yes** | **yes** |
| **JWT claims / signing** | **mandatory** | yes | no | **yes — every Qeet product** |
| Federation contract (SAML/SCIM) | **yes** | yes | maybe | **yes — external, unsurveyable** |
| Webhook payload or signature | **yes** | yes | no | **yes — external** |
| Config / env var | maybe | no | no | deploy repo |
| Dependency bump | maybe | no | no | no |

## Known constraints

- **Product is pre-1.0.** The API contract is not frozen.
- **Tenant isolation is layered.** Principal/path checks and explicit query predicates are the first
  layer; PostgreSQL row-level security protects organisation-owned tables on organisation-admin
  requests. Account-level flows and workers still depend on correct predicates.
- **First-party session access tokens are checked against live session state on each request.** OAuth
  application tokens follow their grant/introspection rules; relying parties must still consume
  revocation/logout signals according to their integration.
- **One PostgreSQL connection target per process.** Replication, failover and backup topology belong
  to deployment infrastructure and cannot be inferred from this repository.
- **Environment availability is external state.** Use `qeet-id-kit` and `qeet-id-deploy` as the
  authority for current DEV/TEST/STAGING and production availability.
- **Rate limiting fails open** when its store errors, and **auth hooks default to fail-open**. Both
  are deliberate, with ADRs. Do not reverse either without reversing the ADR.
- **Cross-context imports are unenforced.**

## Known technical debt

Repository-local documentation was reconciled with `c2454fec` on 15 Nov 2026. New product-level
divergences belong in `qeet-id-context` and its `CONTEXT-CHANGELOG.md`; repository implementation
claims belong here. Keep counts and status claims tied to a verification scope rather than treating
an old audit as current state.

## Documentation authority

| Question | Authority |
|---|---|
| What does the code do? | The source |
| What is the API contract? | `api/openapi/` |
| What is the security policy? | `SECURITY.md`, then L0 `qeet-context/SECURITY.md` |
| How does the product work? | L1 `qeet-id-context` |
| What are the organization rules? | L0 `qeet-context` |
| **How is it implemented here?** | **This document** |

Where a document and the source disagree, **the source is what runs** — and the disagreement is
recorded rather than silently resolved.
