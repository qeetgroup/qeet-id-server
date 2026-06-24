# Qeet ID — Identity Platform

> **Authenticate Everything.** A developer-first, enterprise-ready alternative to Auth0 / Okta — open source, affordable, and built passkeys-first.

[![CI](https://github.com/qeetgroup/qeet-id/actions/workflows/ci.yml/badge.svg)](./.github/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](./go.mod)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1-6BA539?logo=openapiinitiative&logoColor=white)](./api/openapi/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Qeet ID is a single Go **modular monolith** backend plus three React frontends (admin console, marketing site, hosted login) and five first-party SDKs — the complete identity stack: authentication, enterprise SSO/SCIM, fine-grained authorization, machine & AI-agent identity, audit, and compliance. UI primitives come from the shared `@qeetrix/*` design system; end-user docs live in the standalone `qeet-docs` site (docs.qeet.in).

> **Status — pre-1.0, feature-complete for the v1 / July 2026 GA.** Every capability in [Feature status](#feature-status) is implemented and working, with **no stubbed endpoints**. Remaining work is external ops hardening (KMS BYOK, OpenID conformance, deliverability, RDS PITR, external pentest) plus i18n / a11y polish.
>
> | Surface | State |
> | --- | --- |
> | Backend API — ~40 domain modules, 62 migrations, no stubbed endpoints | ✅ complete |
> | Admin console — ~80 feature screens wired to live APIs | ✅ complete |
> | Marketing site · Hosted login | ✅ complete |
> | TypeScript · React · Next.js · Go · Python SDKs | ✅ shipped |

---

## Table of contents

- [Architecture at a glance](#architecture-at-a-glance)
- [Repository layout](#repository-layout)
- [Quickstart](#quickstart)
- [Deployment](#deployment)
- [Testing & quality gates](#testing--quality-gates)
- [Feature status](#feature-status)
- [Tech stack](#tech-stack)
- [Documentation](#documentation)
- [Contributing · Security · License](#contributing)

---

## Architecture at a glance

A **single deployable** Go module organised into **five bounded contexts**, with shared infrastructure grouped by concern under `platform/`. Boundaries are enforced by build-time fitness tests, not convention alone.

```
            ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
 End users  │  login app  │   │   console   │   │   website   │   Browsers / IdPs / SDKs
 Admins     │  (Next.js)  │   │   (Vite)    │   │  (Next.js)  │   service accounts · AI agents
            └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
                   └─────────────────┼─────────────────┘
                                     ▼
        ┌──────────────────────────────────────────────────────────┐
        │  Go API (chi v5)  — cmd/server                            │
        │  middleware: RequestID→RealIP→Recoverer→SecurityHeaders   │
        │              →AccessLog→Tracing→Metrics→CSRF→CORS→authz   │
        │                                                            │
        │  domains/  identity · access · federation · developer ·   │
        │            operations        (interface-mediated calls)   │
        │  platform/ api · database · cache · messaging · events ·  │
        │            observability · security · config              │
        └───────┬───────────────────────────┬──────────────────────┘
                ▼                            ▼
        PostgreSQL (pgx v5)          egress: SMTP · webhooks · SIEM · HIBP
        6 schemas, multi-tenant      (transactional outbox, at-least-once)
        by tenant_id
```

**Engineering invariants** (the things that make it enterprise-grade):

| Invariant | How it's enforced |
| --- | --- |
| Modular-monolith boundaries — `platform/*` never imports `domains/*`; `domains/*` never imports the router/`cmd` | `tests/architecture/arch_test.go` (rules **R1/R2**) fails the build on violation |
| 100% API documentation | `chi.Walk` coverage test fails CI if any mounted route is missing from `api/openapi/` |
| Multi-tenant isolation | every table carries `tenant_id`; 6 PostgreSQL schemas; no cross-schema joins |
| Tamper-evident audit | SHA-256 hash-chained, append-only log with `/verify` integrity walk |
| Reliable eventing | transactional outbox (business row + audit + event in one tx) + DLQ |
| No insecure prod boot | `config.Validate()` refuses to start outside dev with insecure defaults |
| Asymmetric tokens | ES256 / ECDSA P-256, JWKS-published, `kid` = RFC 7638 thumbprint, rotation grace window |

Deep dives live in [`docs/architecture/`](./docs/architecture/) and the decision records in [`docs/adr/`](./docs/adr/).

---

## Repository layout

Single Go module + pnpm/Turbo workspace, both rooted at the repo root.

```
qeet-id/
├── cmd/                    Go entrypoints: server, worker, scheduler, migrate, seed
├── domains/                business logic by bounded context:
│   ├── identity/           users, organizations(+branding), groups, invitations, verification, domains
│   ├── access/             authentication, authorization/{rbac,rebac,policy,authpolicy}, mfa, passkeys,
│   │                       recovery, risk/ipallow, threat-detection/{threat,bot}
│   ├── federation/         oidc, saml, scim, ldap, social
│   ├── developer/          api-keys, service-accounts, credentials/{secrets,vc}, auth-hooks, webhooks, agents
│   └── operations/         audit, analytics, notifications, email-templates, retention, compliance, billing, siem
├── platform/               shared infra by concern:
│   ├── api/                rest (chi router, middleware, paging, errs, codes) · grpc · openapi
│   ├── database/           postgres (pool, dbutil, pgxerr) · migrations (golang-migrate SQL pairs)
│   ├── security/           tokens (ES256/JWKS) · encryption · hibp
│   ├── observability/      logging · metrics · tracing · health · buildinfo
│   ├── events/             outbox (+ DLQ)      cache/  ratelimit
│   └── messaging/ config/  notifier · …
├── apps/                   frontend: console (admin, Vite), website (Next.js), login (Next.js)
├── packages/               shared JS config (qeetid-tsconfig, qeetid-eslint)
├── sdk/                     SDKs: js/{sdk,nextjs,react}, go, python
├── api/                    openapi/ (5 bounded-context OpenAPI 3.1 specs) + postman/ (Newman runner)
├── tests/                  architecture (fitness) · integration (testcontainers) · e2e · performance · security · fixtures
├── deploy/                 base/ (docker incl. Dockerfiles, helm, kubernetes, terraform, observability)
│                           + environments/{dev,test,stage,prod} + runbooks
├── tools/                  codegen · migration-tools · benchmarks · scripts · openapi-split
├── docs/                   architecture · adr · api · security · compliance · onboarding · runbooks
├── Makefile                root targets for the Go module + pnpm workspace
└── ROADMAP.md              planned (not-yet-built) packages & surfaces
```

Folders are organised by domain/concern; some Go **package clauses** differ from the folder name by design — see the table in [CLAUDE.md](./CLAUDE.md#gotchas).

---

## Quickstart

### Prerequisites

- **Go** ≥ 1.25
- **Node.js** ≥ 20.9 with **pnpm** ≥ 9.15.4
- **Docker** & Docker Compose (for PostgreSQL)
- **golang-migrate** CLI ([install](https://github.com/golang-migrate/migrate/tree/master/cmd/migrate))

### 1 · Install

```bash
make install              # go mod tidy + pnpm install
```

### 2 · Database

```bash
cp .env.example .env       # adjust if needed
make db-up                 # Postgres on :5001 (deploy/environments/dev/docker-compose.yml)
make migrate-up            # apply all migrations (platform/database/migrations)
make seed-reset            # (optional) demo workspaces + users to click around
```

`make seed-reset` creates two demo workspaces with users, roles, groups, API keys, webhooks, SSO providers and audit history. Log in with **`owner@acme.test`** (password **`Password123!`**); see [docs/onboarding/quickstart.md](./docs/onboarding/quickstart.md) for all accounts.

### 3 · Run the stack

```bash
make dev                  # backend (:4001) + all 3 frontend apps in parallel
```

| Target | Runs | URL |
| --- | --- | --- |
| `make dev-backend` | Go API | <http://localhost:4001> |
| `make dev-admin` | Admin console (Vite + TanStack) | <http://localhost:3002> |
| `make dev-web` | Marketing site (Next.js) | <http://localhost:3001> |
| `make dev-login` | Hosted login (Next.js) | <http://localhost:3004> |

Sanity check: `curl http://localhost:4001/healthz`. Full target list: `make help`.

---

## Deployment

The backend ships as a **distroless** container ([Dockerfile](./deploy/base/docker/Dockerfile)); migrations ship as a separate one-shot image ([Dockerfile.migrate](./deploy/base/docker/Dockerfile.migrate)). Both build with the **repo root as context** (`docker build -f deploy/base/docker/Dockerfile .`). Pick the path that fits your target:

| Path | Directory | Use |
| --- | --- | --- |
| **Local dev** | [deploy/environments/dev/](./deploy/environments/dev/) | Postgres-only Compose (what `make db-up` uses) |
| **Test** | [deploy/environments/test/](./deploy/environments/test/) | Test-DB Compose (CI is the authoritative test env) |
| **Single host (prod-shaped)** | [deploy/environments/prod/compose/](./deploy/environments/prod/compose/) | Hardened Compose: Caddy TLS + Postgres + Redis + migration one-shot |
| **Kubernetes (kustomize)** | [base/kubernetes/base/](./deploy/base/kubernetes/base/) + [environments/{stage,prod}/kubernetes/](./deploy/environments/) | Shared base + per-env overlays |
| **Kubernetes (Helm)** | [base/helm/qeet-id/](./deploy/base/helm/qeet-id/) + [environments/{stage,prod}/values.yaml](./deploy/environments/) | Chart in base/; values per env. Deployment/Service/Ingress/HPA/PDB + migration Job, External Secrets, ServiceMonitor |
| **AWS infrastructure** | [base/terraform/](./deploy/base/terraform/) + [environments/{stage,prod}/terraform.tfvars](./deploy/environments/) | RDS, ECR, KMS CMK, Secrets Manager; modules in base/, tfvars per env |
| **Observability** | [deploy/base/observability/](./deploy/base/observability/) | Prometheus scrape + alerts, Grafana dashboard, OTel Collector |
| **Runbooks** | [deploy/runbooks/](./deploy/runbooks/) | Operations, secrets generation/rotation, scaling, disaster recovery |

Images are published by CI (cosign-signed, with SBOM + provenance): `ghcr.io/qeetgroup/qeet-id` and `ghcr.io/qeetgroup/qeet-id-migrate`. Start with [deploy/runbooks/operations.md](./deploy/runbooks/operations.md).

---

## Testing & quality gates

Every push and PR runs the full gate set in [CI](./.github/workflows/ci.yml); all are reproducible locally.

| Gate | Local command | Enforces |
| --- | --- | --- |
| Unit + race | `make test-backend` → `go test -race ./...` | Correctness, data races |
| **Architecture fitness** | (part of `go test`) | R1/R2 dependency-direction rules |
| **OpenAPI coverage** | (part of `go test`) | Every mounted route documented in `api/openapi/` |
| **Coverage floor** | `make cover` | Unit coverage can't regress below the floor |
| Go lint | `make lint-go` | `golangci-lint` ([.golangci.yml](./.golangci.yml)) + `go vet` |
| Vulnerabilities | `govulncheck ./...` (CI) | Known CVEs in Go deps |
| Secret scan | `gitleaks` (CI) | No committed credentials |
| OpenAPI lint | `spectral` (CI) | Spec hygiene across the 5 specs |
| Integration | `make test-integration` | Real Postgres via testcontainers (needs Docker) |
| API contract | `make test-api [FOLDER=Auth]` | Postman/Newman against a running backend |
| Frontend | `make test-frontend` · `make typecheck` · `make lint` | Turbo tests, `tsc --noEmit`, ESLint |

```bash
make test          # backend (go test ./...) + frontend (Turbo)
make cover         # unit coverage + enforce floor   ·   make cover-html for the report
make lint          # Go (golangci-lint) + frontend ESLint
```

---

## Feature status

**The full v1 product surface is built and working** — every backend endpoint is implemented (no stubs), every ✅ admin screen is wired to a live API, and the marketing site and hosted login are complete.

<details open>
<summary><b>✅ Available now</b></summary>

**Authentication** — email+password (sessions, refresh rotation) · magic links · email/phone OTP · Passkeys/WebAuthn · social (Google, GitHub, Microsoft, Apple) · MFA (TOTP, recovery codes, email/SMS OTP) · password & passwordless policy.

**Enterprise SSO & provisioning** — OIDC/OAuth 2.0 (discovery, JWKS, authorize/token/userinfo, client registration, Device grant RFC 8628) · Token Exchange RFC 8693 (downscope + delegation) · SAML 2.0 SP **and** IdP modes · SCIM 2.0 (users + groups) · LDAP / Active Directory.

**Identity & access** — multi-tenant tenants & members · users (CRUD, bulk import, sessions, recycle bin) · groups · RBAC + ABAC policies · **ReBAC** (Zanzibar-style relation tuples, recursive `/check`) · invitations · API keys & machine identities (`client_credentials`) · secrets vault (AES-256-GCM, audited, scoped `vault:<name>` reads) · OAuth grant administration.

**Security & compliance** — session management · rate limiting (per IP/tenant/user/API-key) · IP allow/deny (CIDR) · hash-chained audit log (`/verify`) · threat protection (bot + anomaly detection, adaptive limits) · GDPR erasure + grace-period purge · data retention auto-purge · SOC 2 / ISO 27001 / GDPR evidence reporting.

**Developer & platform** — HMAC-signed webhooks (backoff retry + DLQ) · transactional outbox · Auth Hooks/Actions (post-login gate) · SIEM log streaming · **AI-agent identity** (ephemeral scoped revocable tokens + `act` delegation + MCP introspection) · **Verifiable Credentials** (W3C JWT-VC issue/verify/revoke) · five first-party SDKs · analytics.

**Workspace & billing** — branding · custom domains · per-tenant email templates · **multi-currency** billing (any ISO-4217) with card payments via Stripe (international) + Razorpay (India), signature-verified webhooks (env-gated) · account (profile, security, sessions, data export).

</details>

### 🔜 Planned / remaining

- [ ] **CIBA** grant (Client-Initiated Backchannel Auth)
- [ ] Prebuilt **`<SignIn/>` / `<OrgSwitcher/>`** SDK components (`<UserButton/>` already ships in `@qeetid/react`)
- [ ] **i18n** — remaining screens, locale-aware emails, non-English catalogs
- [ ] **WCAG 2.2 AA** — expand the accessibility audit across all screens
- [ ] Managed-cloud infrastructure management (regions, nodes, scaling)
- [ ] **Ops hardening** (not code) — AWS KMS BYOK, OpenID conformance run, deliverability (SPF/DKIM/DMARC), RDS PITR, external pentest

Further planned packages/surfaces are tracked in [ROADMAP.md](./ROADMAP.md).

---

## Tech stack

**Backend** — Go 1.25 · `chi/v5` router · `pgx/v5` Postgres driver · `golang-jwt/jwt/v5` (ES256 + JWKS, key rotation) · `golang.org/x/crypto` (Argon2id) · in-house TOTP (RFC 6238)/HMAC · transactional outbox + webhook dispatcher with DLQ · secrets vault (AES-256-GCM via a `KeyProvider` abstraction; AWS KMS for BYOK). Data access is **hand-written SQL over pgx** (see [ADR-0003](./docs/adr/0003-postgresql-hand-written-sql.md)) — no ORM.

**Frontend** — React 19 everywhere · admin on Vite + TanStack (Router/Query/Form/Table) · web + login on Next.js 16 · Tailwind 4 + the shared `@qeetrix/*` design system · pnpm 9.15 + Turborepo workspace.

**SDKs** — TypeScript (`@qeetid/sdk`), React (`@qeetid/react`), Next.js (`@qeetid/nextjs`), Go (`sdk/go`), Python (`sdk/python`) — all authenticate via `Authorization: ApiKey` + ES256/JWKS verification.

**Infrastructure** — PostgreSQL (Aurora-compatible), 30+ tables across `tenant`/`user`/`auth`/`rbac`/`audit`/`platform` schemas, all multi-tenant by `tenant_id` · optional **Redis** for cross-replica rate limiting (in-process fallback) · Kafka / NATS / object storage planned ([ROADMAP.md](./ROADMAP.md)).

---

## Documentation

| Topic | Where |
| --- | --- |
| Architecture deep-dives (7 docs) | [docs/architecture/](./docs/architecture/) |
| Architecture Decision Records (15) | [docs/adr/](./docs/adr/) |
| Security model & cryptography | [docs/security/](./docs/security/) |
| Compliance (GDPR, data isolation, VC) | [docs/compliance/](./docs/compliance/) |
| Onboarding & contributor guides | [docs/onboarding/](./docs/onboarding/) |
| Operational runbooks | [docs/runbooks/](./docs/runbooks/) · [deploy/runbooks/](./deploy/runbooks/) |
| Codebase tour (new contributors) | [docs/onboarding/codebase-tour.md](./docs/onboarding/codebase-tour.md) |
| Conventions & dev workflow new code must follow | [docs/onboarding/development-workflow.md](./docs/onboarding/development-workflow.md) |
| API spec (OpenAPI 3.1, 5 specs) | [api/openapi/](./api/openapi/) — merge with `go run ./tools/openapi-split merge` |
| Postman collection | [api/postman/](./api/postman/) |
| Runnable example integrations | [examples/](./examples/) — Next.js (server flow) + React SPA (browser PKCE) |
| End-user docs | standalone `qeet-docs` site (docs.qeet.in) |

---

## For AI assistants

Read [CLAUDE.md](./CLAUDE.md) before making changes — it's the top-level brief, with the layout map, commands, and gotchas. New backend code must follow the conventions in [docs/onboarding/development-workflow.md](./docs/onboarding/development-workflow.md) and the deep-dives in [docs/architecture/](./docs/architecture/).

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Bug reports and feature requests go through GitHub Issues using the templates in [.github/ISSUE_TEMPLATE/](./.github/ISSUE_TEMPLATE/).

## Security

Found a vulnerability? **Please do not open a public issue.** Follow the coordinated-disclosure process in [SECURITY.md](./SECURITY.md). Live secrets and `*.pem` keys must never be committed — CI runs `gitleaks` on every push.

## License

[MIT](./LICENSE) © Qeet Group.
