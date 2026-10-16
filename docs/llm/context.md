# Repository Context — qeet-id-server

**Level:** L2 — repository · **Status:** active · **Evidence state:** verified
**Last verified:** 2026-08-28
**Verification scope:** package structure, dependency rules, router wiring, migrations, config
surface, CI jobs and test layout were read from source on this revision. Paths cited under
**Evidence** were confirmed to exist. Claims about the *product* are inherited from L1 and not
re-derived here.

---

## Repository identity

`qeet-id-server` is the **Go backend of Qeet ID**. It is a modular monolith: one Go module, one
PostgreSQL database, one deployable binary, five bounded contexts as enforced package boundaries.

| | |
|---|---|
| Module | `github.com/qeetgroup/qeet-id-server` |
| Language | Go 1.26.0 (toolchain 1.27.2) |
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
requirement, that is a finding recorded in `qeet-id-context/DRIFT-REGISTER.md` — not a redefinition
of the standard.

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
| Hosted login UI | `qeet-id-login` |
| Marketing site | `qeet-id-website` |
| Mobile authenticator | `qeet-id-auth` |
| Client SDKs | `qeet-id-{go,node,react}` |
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
               ↓  RequireAuth            verify JWT: kid, signature, expiry → principal
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
| `/v1` authenticated group | API key → `RequireAuth` → `EnforceTenantScope` → rate limits → `rbac.Enforce` |
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
| `internal/platform` | HTTP, database, crypto, cache, config, events, jobs, messaging, observability |
| `internal/bootstrap` | Composition root: dependencies, router, permission map, lifecycle, server |

77 packages contain Go files.

**File-naming convention — `<domain>.go`, not layered file names.** Domain logic, persistence and
HTTP handlers usually live in **one file named after the package**; additional files split by
**feature**, not by layer. Only four packages use `service.go`/`repository.go` naming and only twelve
have a dedicated `http.go`.

```text
access/passkeys/     passkey.go                          ← everything in one file
developer/agents/    agent.go                            ← everything in one file
access/mfa/          mfa.go  push.go                     ← split by FEATURE
federation/oidc/     oidc.go  device.go  ciba.go  clients_admin.go
identity/users/      domain.go  http.go  repository.go   ← one of the four layered packages
```

**Do not assume a `service.go` or `repository.go` exists** — check
[subsystems.md](subsystems.md) first.

Every leaf package additionally carries `queries.sql` + `sqlc.yaml` + a generated `dbgen/`
(`db.go`, `models.go`, `queries.sql.go`), which is sqlc output and is never hand-edited.

## Dependency rules

**Status:** verified · **Evidence:** `tests/architecture/arch_test.go` — shells out to `go list` and
walks the real import graph

```text
cmd/*  →  internal/bootstrap  →  internal/<context>  →  internal/platform
```

**Two rules are enforced by a build-time test and fail CI:**

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
| `cmd/scheduler` | Scheduled maintenance | Replicas coordinate via **PostgreSQL advisory locks** — safe to run more than one |
| `cmd/migrate` | golang-migrate wrapper | Structured exit codes for init containers |
| `cmd/seed` | Demo data | **Development only.** Drives real services, so hashes and audit chains are real |

---

## Configuration

**Evidence:** `internal/platform/config/config.go` — a single struct with **81 `envconfig` tags**.

Only **two** are required: `DB_URL` and `JWT_SECRET`. Everything else has a default or gates a
capability off. Grouped by concern: service, database, tokens, crypto/KMS, HTTP/CORS/CSRF, URLs,
WebAuthn, social providers, email, SMS, Redis/NATS, billing, password hygiene, observability, AI.

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

One PostgreSQL database, **seven schemas**: `auth`, `tenant`, `user`, `rbac`, `audit`, `platform`,
`qeetai`.

- **Driver:** pgx v5. **Queries:** hand-written SQL in `queries.sql`, compiled by **sqlc** into
  `dbgen/` packages. 48 `queries.sql`/`sqlc.yaml` pairs, 47 `dbgen` directories.
- **Generated `dbgen/` code is never hand-edited.** Change `queries.sql` and regenerate.
- Transactions are opened at the service layer, so a domain write and its outbox row commit together.

### Migrations

**Evidence:** `internal/platform/database/migrations/` — 105 up/down pairs, `0001`–`0106` (`0082` intentionally absent)
(`0082` is absent and must not be reused). Embedded with `//go:embed *.sql` in `runner.go` and
applied on startup.

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

### There is no PostgreSQL RLS

**Verified: zero `ROW LEVEL SECURITY` or `CREATE POLICY` statements across all 105 migrations.**

| Enforcement | A missing `tenant_id` predicate causes |
|---|---|
| RLS | nothing — the database refuses the rows |
| **This repository (application layer)** | **cross-tenant data exposure** |

Isolation holds **while the code is correct**. It is not a database guarantee.

> Two `qeet-id-console` ADRs and one `qeet-id-files` security document assert that RLS is in place.
> They are wrong. Recorded as `qeet-id-context/DRIFT-REGISTER.md` **QID-002** and **QID-003**, both
> `critical`. Do not repeat the claim.

### Restructuring routes is a security change

`internal/bootstrap/router.go` warns that the guard depends on chi's nested-route matching:
flattening the routes onto the top mux makes it **silently fail open**. `rbac` and `users` also
self-scope in-handler; other tenant-scoped resources rely entirely on the middleware.

## Authentication

**Status:** verified
**Evidence:** `internal/platform/crypto/encryption/hasher.go`, `internal/access/authentication/`

Password hashing is **Argon2id** (`m=19456,t=2,p=1`) with transparent upgrade of legacy bcrypt on
successful login. bcrypt remains in use for MFA recovery codes and API-key secrets — a different
requirement, and correct for those.

Implemented mechanisms: password · passkeys (WebAuthn) · magic link · email and SMS OTP · TOTP ·
push approval · social login · adaptive risk (**off by default**) · per-account lockout ·
breached-password check (env-gated).

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
| Tenant policy / password rules | `internal/access/authorization/{policy,authpolicy}/` |

The **route → permission map** lives in `internal/bootstrap/permissions.go` and is consumed by
`rbac.Enforce` as router middleware.

> **Route-level RBAC applies to user JWTs only.** API keys and service principals bypass it and are
> bounded by the scopes encoded in the credential. Scoping at issue time is the control.

## Tokens and cryptography

| Concern | Implementation |
|---|---|
| Algorithm | **ES256 only** — `validMethods` is a one-element allowlist, so `alg` confusion is impossible |
| `kid` | RFC 7638 JWK thumbprint, computed at key load |
| Verification | Missing or unknown `kid` → rejected |
| Rotation | Shared encrypted registry: candidate staging, explicit activation, replica refresh, timed public-key retirement |
| Password hash | Argon2id |
| CSRF token | HMAC-keyed, constant-time comparison |
| Vault | AES-256-GCM, per-tenant HKDF-derived key, static or AWS KMS provider |
| Randomness | `crypto/rand` only |

**Evidence:** `internal/platform/crypto/tokens/{jwt,registry}.go`, `internal/platform/crypto/encryption/`

> There is no signing-key mutation API. `JWT_SIGNING_KEY` stages encrypted key
> material in PostgreSQL; `JWT_ACTIVATE_SIGNING_KEY=true` performs the explicit
> activation step. See `docs/JWT-KEY-ROTATION.md`.

## Federation

**Status:** verified · **Evidence:** `internal/federation/`, `internal/bootstrap/router.go`

Qeet ID is both a **service provider** (consuming a customer IdP over SAML, LDAP or social) and an
**identity provider** (OIDC, and SAML IdP for customer SPs).

Protocol endpoints are mounted at the **root, not under `/v1`**, because the specifications require
fixed locations — `.well-known/*`, `/scim/v2`, `/saml/*`, `/ldap/*`. `/oauth/introspect` and
`/oauth/revoke` also sit at the root, which is a deviation from the L0 URL standard: deliberate, and
advertised in the discovery document (`qeet-id-context` QID-005).

**SAML, SCIM and LDAP parse untrusted external input** — the highest-risk surface in this repository.

**Per-package file pointers: [subsystems.md](subsystems.md#federation).**

## Developer, machine and agent identity

**Status:** verified · **Evidence:** `internal/developer/`

Three non-human identity forms: **API keys** (`qk_`, stored as `<prefix>.<secret>` with a bcrypt
hash), **service principals** (`client_credentials`, short-lived service JWT scoped to one tenant),
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

**Evidence:** `internal/platform/events/outbox/`, `internal/platform/jobs/worker.go`

Workers run **embedded in `cmd/api` by default**; set `EMBEDDED_WORKERS=false` when `cmd/worker`
runs them standalone. Webhook, outbox, and GDPR queues use durable PostgreSQL leases with
owner-conditional finalization; retries retain stable event/delivery IDs. Registered workers:
webhooks, audit anomaly, GDPR, retention, SIEM, outbox dispatch.

`cmd/scheduler` runs low-frequency tenant-wide maintenance, coordinated by PostgreSQL advisory locks
so multiple replicas are safe.

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
There is deliberately no monolithic spec.

**The coverage gate is the important part:** `tests/integration/coverage_test.go` fails the build if
any mounted route is undocumented. A route cannot silently appear.

**A route change and its spec change belong in the same commit.**

> The specs list only `localhost` servers — production `api.id.qeet.in` appears in none of them
> (`qeet-id-context` QID-004). Do not treat the spec as a working client configuration.

## Testing

| Suite | Path | Runs |
|---|---|---|
| Unit | alongside source | `go test ./...` |
| **Architecture fitness** | `tests/architecture/` | with unit tests — enforces R1/R2 |
| Integration | `tests/integration/` (18 files) | `-tags integration`, Testcontainers |
| **OpenAPI coverage gate** | `tests/integration/coverage_test.go` | integration tag |
| Security regression | `tests/security/` | auth bypass, CSRF, headers |
| Semgrep rule | `tests/security/semgrep/no-raw-sql-fmt.yaml` | no `fmt`-built SQL |
| Performance | `tests/performance/` | k6, not CI-wired |

CI runs unit tests with `-race`. Unit tests are **colocated** (`_test.go` beside the source,
in-package) — 69 of them. There is no `testdata/` or `mocks/` directory.

**Coverage gaps worth knowing before you change these:**

| Package | Unit tests |
|---|---|
| **`internal/bootstrap`** | **none** — the router, permission map and wiring are covered *only* by `tests/integration/` |
| `identity/{tenant,groups,invitations,verification}` | none — integration only |
| `access/recovery`, `access/authorization/authzen` | none — integration only |
| `developer/principal`, `operations/notifications` | none — integration only |

`internal/bootstrap/permissions_test.go` walks the exact authenticated production mounts and
requires an explicit route policy. `internal/bootstrap/openapi_coverage_test.go` walks all three
production mount helpers and compares them bidirectionally with the union of the five OpenAPI
documents, including API-auth security classification. Integration tests remain the cross-cutting
behavioral and database layer — see [subsystems.md](subsystems.md).

## CI/CD

| Job | What it runs |
|---|---|
| `test` | `go build ./...` · `go vet ./...` · `go test -race -count=1 ./...` |
| `lint` | `golangci-lint` v2.14.0 — new code only |
| `integration` | `go test -tags integration -timeout 10m ./tests/integration/...` |
| `vuln` | `govulncheck ./cmd/... ./internal/...` blocking · advisory full-tree scan |
| `sast` | `gosec` — advisory |
| `deploy` | On push to `main`: build, deploy to AWS via GitHub OIDC, then tag |

`.golangci.yml` enables `errcheck`, `govet`, `staticcheck`, `misspell` plus `gofmt`/`goimports`;
`dbgen` packages are excluded.

**`make lint` runs `go vet` only** — it is not the CI lint. Passing it locally does not mean CI
lint passes.

## Deployment

**This repository builds a container. It does not own its deployment.**

- `Dockerfile` — build on `golang:1.27.2-alpine` (same Go as go.mod's toolchain), ship on `gcr.io/distroless/static-debian12:nonroot`,
  non-root user, `EXPOSE 4001`.
- `docker-compose.yml` — **local dependencies only**: postgres :5001, nats :4222, mailpit :8025.
- Terraform, Caddy, compose for production and the rollout live in **`qeet-id-deploy`**.
- `.github/workflows/deploy.yml` pushes to AWS on merge to `main`.

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

Then `make test`, `make test-integration`, `make lint`, `make build`.
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
| **Hashing, vault crypto** | `internal/platform/crypto/encryption/` | **Critical** | Security review |
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
- **Tenant isolation is application-layer**, not database-enforced.
- **Access-token revocation is bounded by the 10-minute TTL** — there is no per-request database
  revocation check.
- **Single PostgreSQL instance**, no read replica. It is the single point of failure.
- **No staging environment exists** — `api.id.staging.qeet.in` does not resolve.
- **Rate limiting fails open** when its store errors, and **auth hooks default to fail-open**. Both
  are deliberate, with ADRs. Do not reverse either without reversing the ADR.
- **Cross-context imports are unenforced.**

## Known technical debt

Repository-local documentation inconsistencies found on this revision. Product-level drift lives in
`qeet-id-context/DRIFT-REGISTER.md`; these are the ones local to this repository:

| Issue | Detail |
|---|---|
| `ROADMAP.md` SDK count | Claims 6 SDK packages; three repositories exist (QID-008) |
| `ROADMAP.md` ✅ rows in the planned table | Two shipped items sit under "Planned" (QID-018) |
| Old `CLAUDE.md` Make targets | Claimed a "complete" set that omitted `dev-secrets`, `test-integration`, `bench` |
| Old `CLAUDE.md` `.claude/` agents | Referenced `.claude/agents/*` — **no `.claude/` directory exists** (QID-020) |

## Current vs planned

**Current:** everything described above. **Planned, per `ROADMAP.md`** — auth-hook claims in the
OIDC ID-token path, remaining i18n, WCAG 2.2 AA on legacy screens, published benchmarks,
device-bound agent credentials, a `qeetid` CLI, FGA permissions index, Rust SDK, SCIM agent
extension, Kubernetes + Helm, multi-environment staging, a bundled observability stack.

**A roadmap entry is not implementation evidence.** Verify against source before relying on any
capability.

## Documentation authority

| Question | Authority |
|---|---|
| What does the code do? | The source |
| What is the API contract? | `api/openapi/` |
| What is shipped vs planned? | `ROADMAP.md` — with the staleness caveats above |
| What is the security policy? | `SECURITY.md`, then L0 `qeet-context/SECURITY.md` |
| How does the product work? | L1 `qeet-id-context` |
| What are the organization rules? | L0 `qeet-context` |
| **How is it implemented here?** | **This document** |

Where a document and the source disagree, **the source is what runs** — and the disagreement is
recorded rather than silently resolved.
