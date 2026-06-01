# Qeet ID — Identity Platform

> **Authenticate Everything.** A developer-first, enterprise-ready alternative to Auth0 / Okta — open source, affordable, and built around passkeys-first authentication.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

This monorepo contains the full Qeet ID identity platform: a Go modular-monolith backend, three frontend apps (admin dashboard, marketing site, docs), and a shared UI component library.

> **Status:** pre-1.0, but substantially built out — **~88% of the v1 product surface is implemented and working.**
>
> | Surface | Completion |
> | --- | --- |
> | Backend API — 28 domain modules, 40 migrations, **no stubbed endpoints** | ~90% |
> | Admin console — **56 / 63 feature screens wired to live APIs** | ~89% |
> | Marketing site (`qeetid-web`) | ✅ complete |
> | Docs site (`qeetid-docs`) | ✅ complete |
>
> Remaining work is mostly net-new feature areas (automation, threat-detection, secrets vault), informational compliance pages, and production hardening (real email/SMS delivery, stronger crypto). Full breakdown in [Feature status](#feature-status).

---

## Repository layout

```
qeet-identity/
├── backend/                Go API server (chi + pgx + PostgreSQL)
│   ├── api/
│   │   ├── openapi.yaml    OpenAPI 3.x specification
│   │   └── postman/        Postman collection + Newman runner
│   ├── cmd/server/         Service entrypoint
│   ├── internal/           28 domain modules (auth, oidc, rbac, mfa, saml, scim, ldap, billing, secret, …)
│   ├── migrations/         39 SQL migrations (golang-migrate)
│   └── Makefile            Backend build / test / migrate targets
├── frontend/               pnpm + Turborepo workspace
│   ├── apps/
│   │   ├── qeetid-admin/   Admin dashboard (Vite + TanStack Router)
│   │   ├── qeetid-web/     Marketing site (Next.js)
│   │   └── qeetid-docs/    Docs site (Next.js + fumadocs)
│   └── packages/
│       ├── qeetid-ui/         Shared shadcn-style components
│       ├── qeetid-tsconfig/   Shared TypeScript configs
│       └── qeetid-eslint/     Shared ESLint config
├── docker-compose.yml      Whole-stack (Postgres + backend, opt-in frontend)
└── Makefile                Root targets that delegate into backend/ + frontend/
```

---

## Quickstart

### Prerequisites

- **Go** ≥ 1.22
- **Node.js** ≥ 20 with `pnpm` ≥ 9.15.4
- **Docker** & **Docker Compose** (for PostgreSQL)
- **golang-migrate** CLI ([install](https://github.com/golang-migrate/migrate/tree/master/cmd/migrate))

### 1. Install dependencies

```bash
make install              # go mod tidy + pnpm install
```

### 2. Bring up the database

```bash
cp backend/.env.example backend/.env   # adjust if needed
make db-up                # Postgres on :5001 (Docker)
make migrate-up           # apply all migrations
make seed-reset           # (optional) fill the DB with demo data to click around
```

`make seed-reset` creates two demo workspaces with users, roles, groups, API
keys, webhooks, SSO providers and audit history. Log in with `owner@acme.test`
(password `Password123!`); see [backend/README.md](./backend/README.md#seed-demo-data) for all accounts.

### 3. Run the stack

```bash
make dev                  # backend (:4000) + all 3 frontend apps in parallel
```

Or run pieces individually:

| Target              | What it runs                          | URL                                            |
| ------------------- | ------------------------------------- | ---------------------------------------------- |
| `make dev-backend`  | Go API                                | <http://localhost:4000>                        |
| `make dev-admin`    | Admin dashboard (Vite + TanStack)     | <http://localhost:3002>                        |
| `make dev-web`      | Marketing site (Next.js)              | <http://localhost:3001>                        |
| `make dev-docs`     | Docs site (Next.js + fumadocs)        | <http://localhost:3003>                        |

Sanity check the API: `curl http://localhost:4000/healthz`.

### Docker-only path (no Go toolchain)

```bash
docker compose up -d      # Postgres :5001 + backend :4001
docker compose --profile frontend up    # also runs all 3 frontend containers
```

See the full target list with `make help` or in [Makefile](./Makefile).

---

## Tests and quality

```bash
make test                 # backend (go test ./...) + frontend (Turbo)
make test-backend         # Go only
make test-frontend        # JS/TS only
make test-api             # Postman collection via Newman — backend must be up
make test-api FOLDER=Auth # scope to one Postman folder

make lint                 # go vet + frontend eslint
make typecheck            # frontend tsc --noEmit
make format               # frontend prettier
```

CI-style API run with JUnit + HTML reports: `make test-api-ci` (artifacts land under [backend/api/postman/reports/](./backend/api/postman/)).

---

## Feature status

**~85% of the v1 product surface is built and working** — every backend endpoint below is implemented (no stubs), and every ✅ admin screen is wired to a live API. The marketing site and docs are complete.

### ✅ Available now

**Authentication**

- [x] Email + password, sessions, refresh-token rotation
- [x] Magic links — passwordless email links + tenant config (enable, link lifetime)
- [x] Email & phone OTP verification
- [x] Passkeys / WebAuthn — full register + login ceremony
- [x] Social login — Google, GitHub, Microsoft, Apple
- [x] MFA — TOTP, recovery codes, Email/SMS one-time-passcode factors
- [x] Password & passwordless policy — complexity rules (enforced on password change) + method toggles

**Enterprise SSO & provisioning**

- [x] OIDC / OAuth 2.0 — discovery, JWKS, `/authorize`, `/token`, userinfo, client registration
- [x] SAML 2.0 (SP) — connection management, SP metadata, AuthnRequest, signature-validated ACS, JIT provisioning, `/sso/callback`
- [x] SCIM 2.0 — per-tenant bearer token + `/scim/v2/Users` (create / filter / patch-active / delete)
- [x] LDAP / Active Directory — service-bind, user search, password verification, JIT provisioning

**Identity & access**

- [x] Multi-tenant tenants & members
- [x] Users — CRUD, bulk import, sessions, recycle bin (restore / permanent purge)
- [x] Groups
- [x] RBAC roles & permissions, ABAC policies, resource catalogue
- [x] Invitations
- [x] API keys & machine identities (OAuth `client_credentials`)
- [x] Secrets vault — named integration secrets, AES-256-GCM encrypted at rest, audited reveal
- [x] OAuth grant administration — list / revoke active OIDC refresh-token grants

**Security & compliance**

- [x] Session management
- [x] Rate limiting — per-IP / per-tenant / per-user / per-API-key
- [x] IP allow / deny rules — CIDR, deny-wins, evaluation endpoint
- [x] Audit log — hash-chained, append-only
- [x] GDPR erasure requests + grace-period purge sweeper
- [x] Data retention — opt-in auto-purge of soft-deleted users (+ preview / run-now)

**Developer & platform**

- [x] Webhooks — HMAC-signed, exponential-backoff retry, DLQ
- [x] Transactional outbox + dispatcher
- [x] Analytics overview

**Workspace & billing**

- [x] Branding
- [x] Workspace settings + custom domains
- [x] Transactional email templates — per-tenant overrides + preview
- [x] Billing — **internal, multi-currency** plans / subscriptions / invoices (any ISO-4217 currency)
- [x] Account — profile, security, sessions, data export

**Apps**

- [x] Admin dashboard (Vite + TanStack Router)
- [x] Marketing site (Next.js)
- [x] Docs site (Next.js + fumadocs, AI search)

### 🔜 Planned / not yet implemented

- [ ] **Bots & automations** — event-triggered workflow rules
- [ ] **Infrastructure** management — regions, nodes, scaling
- [ ] **Threat-protection dashboards** — bot detection, anomaly detection, adaptive rate limits
- [ ] **Compliance evidence pages** — SOC 2, ISO 27001 (reporting / export)
- [ ] Production **email / SMS delivery** — `Sender` is log-only today; pluggable for SendGrid / Twilio / Resend
- [ ] **SAML IdP mode** (SP is done) and **SCIM Groups**
- [ ] **Crypto hardening** — Argon2id password hashing, RS256/ES256 JWT signing + key rotation

---

## Requirements traceability

Product requirements are published upstream at [qeetgroup/qeetify · qeetify-reqs](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs) across three discovery / design phases. Current implementation status against those requirements is tracked in [Feature status](#feature-status) above.

---

## Tech stack

**Backend**

- Go 1.22, `chi/v5` router, `pgx/v5` PostgreSQL driver
- `golang-jwt/jwt/v5`, `golang.org/x/crypto` (bcrypt — migrating to Argon2id)
- In-house TOTP (RFC 6238), HMAC, token codes
- Transactional outbox for event publishing, with DLQ + webhook dispatcher

**Frontend**

- React 19 across all apps
- Admin: Vite 8 + TanStack Router 1.170 + TanStack Query + TanStack Form + TanStack Table
- Web + Docs: Next.js 16
- Docs: fumadocs + Flexsearch + AI search (OpenRouter)
- Tailwind 4, shadcn-style components built on Base UI
- Workspace: pnpm 9.15 + Turborepo 2.9

**Infrastructure**

- PostgreSQL (Aurora-compatible) — 30+ tables across `tenant`, `user`, `auth`, `rbac`, `audit`, `platform` schemas, all multi-tenant by `tenant_id`
- Redis, Kafka, S3 — planned per [Phase 2 High-Level Architecture](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs/phase-2)

---

## Documentation

- **Implementation status** — [Feature status](#feature-status)
- **Backend module guide** — [backend/README.md](./backend/README.md)
- **End-user docs** — `make dev-docs` → <http://localhost:3003>
- **API spec (in progress)** — [backend/api/openapi.yaml](./backend/api/openapi.yaml)
- **Postman collection** — [backend/api/qeet-identity.postman_collection.json](./backend/api/qeet-identity.postman_collection.json)

---

## For AI assistants

This repo has a Claude-flavoured operational layer:

- [CLAUDE.md](./CLAUDE.md) — top-level brief for any AI assistant working in this codebase.
- [.claude/rules/](./.claude/rules/) — topic-scoped rules (backend, frontend, database, security, api, testing, git-workflow, docs).
- [.claude/skills/](./.claude/skills/) — workflow skills (`add-endpoint`, `release-readiness`, `gap-fill`).
- [.claude/commands/](./.claude/commands/) — slash commands (`/routes`, `/migration-new`, `/module-new`, `/feature-status`, `/api-test`, `/audit-check`).
- [.claude/agents/](./.claude/agents/) — review agent (`qeetid-reviewer`) wired into the PR flow.

Read [CLAUDE.md](./CLAUDE.md) before making changes if you're a model. Humans see [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Bug reports and feature requests go through GitHub Issues using the templates in [.github/ISSUE_TEMPLATE/](./.github/ISSUE_TEMPLATE/).

## Security

Found a vulnerability? **Please do not open a public issue.** Follow the disclosure process in [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE) © Qeet Group.
