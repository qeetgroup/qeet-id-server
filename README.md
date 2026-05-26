# QEETID — Identity Platform

> **Authenticate Everything.** A developer-first, enterprise-ready alternative to Auth0 / Okta — open source, affordable, and built around passkeys-first authentication.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

This monorepo contains the full Qeetid identity platform: a Go modular-monolith backend, three frontend apps (admin dashboard, marketing site, docs), and a shared UI component library.

---

## Repository layout

```
qeet-identity/
├── backend/         Go API server (chi + pgx + PostgreSQL)
│   ├── api/         OpenAPI 3.x specification
│   ├── cmd/server/  Service entrypoint
│   ├── internal/    Domain modules (auth, oidc, rbac, mfa, …)
│   ├── migrations/  SQL migrations (golang-migrate)
│   └── Makefile     Backend build / test / migrate targets
├── frontend/        pnpm + Turborepo workspace
│   ├── apps/
│   │   ├── qeetid-admin/  Admin dashboard (Vite + TanStack Router)
│   │   ├── qeetid-web/    Marketing site (Next.js)
│   │   └── qeetid-docs/   Docs site (Next.js + fumadocs)
│   └── packages/
│       ├── qeetid-ui/        Shared shadcn-style components
│       ├── qeetid-tsconfig/  Shared TypeScript configs
│       └── qeetid-eslint/    Shared ESLint config
└── documents/       Implementation status & requirement traceability
    ├── README.md                  Index
    ├── IMPLEMENTATION-STATUS.md   Module-by-module status
    ├── FEATURE-MATRIX.md          Quick-reference table
    ├── PROTOCOL-STATUS.md         OAuth/OIDC/SAML/SCIM/WebAuthn conformance
    └── GAP-ANALYSIS.md            Prioritized punch list to v1.0
```

---

## Quickstart

### Prerequisites

- **Go** ≥ 1.22
- **Node.js** ≥ 20 with `pnpm` ≥ 9.15.4
- **Docker** & **Docker Compose** (for PostgreSQL)
- **golang-migrate** CLI ([install](https://github.com/golang-migrate/migrate/tree/master/cmd/migrate))

### 1. Bring up the database

```bash
cd backend
cp .env.example .env       # adjust if needed
docker compose up -d       # starts Postgres on :5001
make migrate-up            # apply 21 migrations
```

### 2. Run the backend

```bash
cd backend
make run                   # starts API on :8080
```

Verify: `curl http://localhost:8080/healthz`

### 3. Run the frontend apps

```bash
cd frontend
pnpm install
pnpm dev                   # all three apps via Turbo
```

Individual apps:

- `pnpm dev:admin` → admin dashboard at <http://localhost:3002>
- `pnpm dev:web` → marketing site at <http://localhost:3001>
- `pnpm dev:docs` → docs site at <http://localhost:3003>

### 4. One-command full-stack dev (optional)

From the repo root:

```bash
make dev                   # runs backend + all 3 frontend apps via Make
```

See [Makefile](./Makefile) for the full target list.

---

## What works today

See [documents/IMPLEMENTATION-STATUS.md](./documents/IMPLEMENTATION-STATUS.md) for the full module-by-module status. Highlights:

| Area                                                           | Status                                                |
| -------------------------------------------------------------- | ----------------------------------------------------- |
| Email / password auth + session + refresh-token rotation       | ✅                                                    |
| Magic link + email OTP + phone OTP                             | ✅                                                    |
| MFA (TOTP + recovery codes)                                    | ✅                                                    |
| Multi-tenant RBAC with permission check API                    | ✅                                                    |
| API keys + service-account M2M (OAuth client_credentials)      | ✅                                                    |
| Webhooks (HMAC-signed, exponential-backoff retry)              | ✅                                                    |
| Audit log                                                      | ✅                                                    |
| OIDC discovery / JWKS / dynamic client registration / userinfo | ✅                                                    |
| GDPR erasure request intake                                    | 🟡 (purge job scaffolded)                             |
| WebAuthn passkey ceremony                                      | 🔴 (storage ready, ceremony returns 501)              |
| Social OAuth (Google / GitHub / Microsoft / Apple)             | 🔴 (provider config ready, exchange flow returns 501) |
| SAML 2.0 SP/IdP                                                | 🔴                                                    |
| SCIM 2.0                                                       | 🔴                                                    |
| Admin dashboard screens beyond `/dashboard`                    | 🔴 (38 routes are catch-all placeholders)             |
| Stripe billing                                                 | 🔴                                                    |

Headline: **~29% of v1.0 must-haves implemented, ~16% partial, ~55% not started**. See [documents/GAP-ANALYSIS.md](./documents/GAP-ANALYSIS.md) for the prioritized punch list to v1.0.

---

## Requirements traceability

Product requirements are published upstream at [qeetgroup/qeetify · qeetify-reqs](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs) across three discovery / design phases. The [documents/](./documents/) folder maps each requirement to its implementation status in this repo.

---

## Tech stack

**Backend**

- Go 1.22, `chi/v5` router, `pgx/v5` PostgreSQL driver
- `golang-jwt/jwt/v5`, `golang.org/x/crypto` (bcrypt — migrating to Argon2id)
- In-house TOTP (RFC 6238), HMAC, token codes
- Transactional outbox for event publishing

**Frontend**

- React 19 across all apps
- Admin: Vite 8 + TanStack Router 1.170 + TanStack Query + TanStack Form + TanStack Table
- Web + Docs: Next.js 16
- Docs: fumadocs + Flexsearch + AI search (OpenRouter)
- Tailwind 4, shadcn-style components built on Base UI
- Workspace: pnpm 9.15 + Turborepo 2.9

**Infrastructure**

- PostgreSQL (Aurora-compatible) — 30+ tables across `tenant`, `user`, `auth`, `rbac`, `audit`, `platform` schemas
- Redis, Kafka, S3 — planned per [Phase 2 High-Level Architecture](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs/phase-2)

---

## Documentation

- **Implementation status** — [documents/](./documents/)
- **Backend module guide** — [backend/README.md](./backend/README.md)
- **End-user docs** — run `pnpm dev:docs` → <http://localhost:3003>
- **API spec (in progress)** — [backend/api/openapi.yaml](./backend/api/openapi.yaml)

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Bug reports and feature requests go through GitHub Issues using the templates in `.github/ISSUE_TEMPLATE/`.

## Security

Found a vulnerability? **Please do not open a public issue.** Follow the disclosure process in [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE) © Qeet Group.
