# Qeet ID — Identity Platform

> **Authenticate Everything.** A developer-first, enterprise-ready alternative to Auth0 / Okta — open source, affordable, and built around passkeys-first authentication.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

This monorepo contains the full Qeet ID identity platform: a Go modular-monolith backend, three frontend apps (admin dashboard, marketing site, docs), and a shared UI component library.

> **Status:** pre-1.0. Roughly **29% of v1.0 must-haves implemented, 16% partial, 55% not started** — see [documents/IMPLEMENTATION-STATUS.md](./documents/IMPLEMENTATION-STATUS.md) and [documents/GAP-ANALYSIS.md](./documents/GAP-ANALYSIS.md) before betting your product on it.

---

## Repository layout

```
qeet-identity/
├── backend/                Go API server (chi + pgx + PostgreSQL)
│   ├── api/
│   │   ├── openapi.yaml    OpenAPI 3.x specification
│   │   └── postman/        Postman collection + Newman runner
│   ├── cmd/server/         Service entrypoint
│   ├── internal/           ~20 domain modules (auth, oidc, rbac, mfa, …)
│   ├── migrations/         25 SQL migrations (golang-migrate)
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
├── documents/              Implementation status & requirement traceability
│   ├── README.md                  Index
│   ├── IMPLEMENTATION-STATUS.md   Module-by-module status
│   ├── FEATURE-MATRIX.md          Quick-reference table
│   ├── PROTOCOL-STATUS.md         OAuth/OIDC/SAML/SCIM/WebAuthn conformance
│   └── GAP-ANALYSIS.md            Prioritized punch list to v1.0
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
make migrate-up           # apply all 25 migrations
```

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

## What works today

See [documents/IMPLEMENTATION-STATUS.md](./documents/IMPLEMENTATION-STATUS.md) for the full module-by-module status. Highlights:

| Area                                                           | Status                                                |
| -------------------------------------------------------------- | ----------------------------------------------------- |
| Email / password auth + session + refresh-token rotation       | ✅                                                    |
| Magic link + email OTP + phone OTP                             | ✅                                                    |
| MFA (TOTP + recovery codes)                                    | ✅                                                    |
| Multi-tenant RBAC with permission check API                    | ✅                                                    |
| API keys + service-account M2M (OAuth client_credentials)      | ✅                                                    |
| Webhooks (HMAC-signed, exponential-backoff retry, DLQ)         | ✅                                                    |
| Audit log (hash-chained, append-only)                          | ✅                                                    |
| Transactional outbox + webhook dispatcher                      | ✅                                                    |
| OIDC discovery / JWKS / dynamic client registration / userinfo | ✅                                                    |
| Password hashing                                               | 🟡 (bcrypt cost 12 — migrating to Argon2id)           |
| JWT signing                                                    | 🟡 (HS256 today — RS256/ES256 + rotation needed)      |
| OAuth 2.0 Authorization Code + OIDC ID-token issuance          | 🔴 (`/authorize` + code-grant `/token` missing)       |
| GDPR data export + erasure runner                              | 🟡 (intake done, purge `Run()` is a no-op)            |
| WebAuthn passkey ceremony                                      | 🔴 (storage ready, all 4 ceremony endpoints 501)      |
| Social OAuth (Google / GitHub / Microsoft / Apple)             | 🔴 (provider config ready, exchange flow 501)         |
| SAML 2.0 SP/IdP                                                | 🔴                                                    |
| SCIM 2.0                                                       | 🔴                                                    |
| Admin dashboard screens beyond `/dashboard`                    | 🔴 (38 routes are catch-all placeholders)             |
| Real email / SMS senders                                       | 🔴 (`Sender` interface is `LogSender` — stdout only)  |
| Stripe billing                                                 | 🔴                                                    |

The full launch-blocker list is in [documents/GAP-ANALYSIS.md](./documents/GAP-ANALYSIS.md).

---

## Requirements traceability

Product requirements are published upstream at [qeetgroup/qeetify · qeetify-reqs](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs) across three discovery / design phases. The [documents/](./documents/) folder maps each requirement to its implementation status in this repo.

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

- **Implementation status** — [documents/](./documents/)
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
