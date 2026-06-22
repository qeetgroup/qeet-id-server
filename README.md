# Qeet ID — Identity Platform

> **Authenticate Everything.** A developer-first, enterprise-ready alternative to Auth0 / Okta — open source, affordable, and built around passkeys-first authentication.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

This monorepo contains the full Qeet ID identity platform: a Go modular-monolith backend and three frontend apps (admin dashboard, marketing site, hosted login). UI primitives come from the shared `@qeetrix/*` design system. (End-user docs now live in the standalone multi-product `qeet-docs` site, no longer in this repo.)

> **Status:** pre-1.0, **feature-complete for the v1 / July 2026 GA** — every capability below is implemented and working, with **no stubbed endpoints**.
>
> | Surface | State |
> | --- | --- |
> | Backend API — **~40 domain modules, 62 migrations, no stubbed endpoints** | ✅ complete |
> | Admin console — **~80 feature screens wired to live backend APIs** | ✅ complete |
> | Marketing site (`qeetid-web`) | ✅ complete |
> | Hosted login (`qeetid-login`) | ✅ complete |
>
> Remaining work is **external ops hardening** (AWS KMS BYOK setup, OpenID conformance run, email/SMS deliverability, RDS PITR, external pentest), plus a few prebuilt SDK components and **i18n / a11y** polish. Full breakdown in [Feature status](#feature-status).

---

## Repository layout

Single Go module + pnpm/Turbo workspace, both rooted at the repo root.

```
qeet-id/
├── cmd/                    Go entrypoints (server, seed)
├── domains/                business logic by bounded context:
│   ├── identity/           users, organizations(+branding), groups, invitations, verification, domains
│   ├── access/             authentication, authorization/{rbac,rebac,policy,authpolicy}, mfa, passkeys,
│   │                       recovery, risk/ipallow, threat-detection/{threat,bot}
│   ├── federation/         oidc, saml, scim, ldap, social
│   ├── developer/          api-keys, service-accounts, credentials/{secrets,vc}, auth-hooks, webhooks, agents
│   └── operations/         audit, analytics, notifications, email-templates, retention, compliance, billing, siem
├── platform/               shared infra (db, tokens, httpx, http router/wiring, config, logger, …)
├── apps/                   frontend: console (admin, Vite), website (Next.js), login (Next.js) [+ docs/, status/]
├── packages/               shared JS config (qeetid-tsconfig, qeetid-eslint)
├── sdk/                    SDKs: js/{sdk,nextjs,react}, go, python
├── api/                    openapi.yaml (OpenAPI 3.x) + postman/ (Newman runner)
├── migrations/             62 SQL migrations (golang-migrate)   ·   sqlc/  codegen inputs
├── tests/                  Go integration tests (testcontainers)
├── deploy/                 Compose (prod), Helm chart, observability, RUNBOOK
├── Dockerfile(.migrate)    Distroless app image + migration runner (build context = repo root)
└── Makefile                Root targets for the Go module + pnpm workspace
```

---

## Quickstart

### Prerequisites

- **Go** ≥ 1.25
- **Node.js** ≥ 20 with `pnpm` ≥ 9.15.4
- **Docker** & **Docker Compose** (for PostgreSQL)
- **golang-migrate** CLI ([install](https://github.com/golang-migrate/migrate/tree/master/cmd/migrate))

### 1. Install dependencies

```bash
make install              # go mod tidy + pnpm install
```

### 2. Bring up the database

```bash
cp .env.example .env       # adjust if needed
make db-up                 # Postgres on :5001 (Docker)
make migrate-up            # apply all migrations
make seed-reset            # (optional) fill the DB with demo data to click around
```

`make seed-reset` creates two demo workspaces with users, roles, groups, API
keys, webhooks, SSO providers and audit history. Log in with `owner@acme.test`
(password `Password123!`); see [docs/BACKEND.md](./docs/BACKEND.md#seed-demo-data) for all accounts.

### 3. Run the stack

```bash
make dev                  # backend (:4001) + all 3 frontend apps in parallel
```

Or run pieces individually:

| Target              | What it runs                          | URL                                            |
| ------------------- | ------------------------------------- | ---------------------------------------------- |
| `make dev-backend`  | Go API                                | <http://localhost:4001>                        |
| `make dev-admin`    | Admin dashboard (Vite + TanStack)     | <http://localhost:3002>                        |
| `make dev-web`      | Marketing site (Next.js)              | <http://localhost:3001>                        |
| `make dev-login`    | Hosted login (Next.js)                | <http://localhost:3004>                        |

Sanity check the API: `curl http://localhost:4001/healthz`.

### Containerised paths

```bash
make db-up     # docker-compose.yml — Postgres only (dev)
```

For a production-shaped stack (backend + Postgres + Redis + TLS proxy + migration
one-shot) use the Compose file under [deploy/compose/](./deploy/compose/); the Helm
chart in [deploy/helm/qeet-id/](./deploy/helm/qeet-id/) is the Kubernetes target. See
[deploy/RUNBOOK.md](./deploy/RUNBOOK.md).

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

CI-style API run with JUnit + HTML reports: `make test-api-ci` (artifacts land under [api/postman/reports/](./api/postman/)).

---

## Feature status

**The full v1 product surface is built and working** — every backend endpoint below is implemented (no stubs), and every ✅ admin screen is wired to a live API. The marketing site and hosted login are complete.

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

- [x] OIDC / OAuth 2.0 — discovery, JWKS, `/authorize`, `/token`, userinfo, client registration, Device grant (RFC 8628)
- [x] Token Exchange (RFC 8693) — token downscope + delegation (`actor_token` / `act` claim)
- [x] SAML 2.0 (SP) — connection management, SP metadata, AuthnRequest, signature-validated ACS, JIT provisioning, `/sso/callback`
- [x] SCIM 2.0 — per-tenant bearer token + `/scim/v2/Users` (create / filter / patch-active / delete)
- [x] LDAP / Active Directory — service-bind, user search, password verification, JIT provisioning

**Identity & access**

- [x] Multi-tenant tenants & members
- [x] Users — CRUD, bulk import, sessions, recycle bin (restore / permanent purge)
- [x] Groups
- [x] RBAC roles & permissions, ABAC policies, resource catalogue
- [x] ReBAC — relationship-based, Zanzibar-style fine-grained authz (relation tuples, recursive userset `/check`)
- [x] Invitations
- [x] API keys & machine identities (OAuth `client_credentials`)
- [x] Secrets vault — named integration secrets, AES-256-GCM encrypted at rest, audited reveal; scoped vault reads (`vault:<name>`) for delegated agents
- [x] OAuth grant administration — list / revoke active OIDC refresh-token grants

**Security & compliance**

- [x] Session management
- [x] Rate limiting — per-IP / per-tenant / per-user / per-API-key
- [x] IP allow / deny rules — CIDR, deny-wins, evaluation endpoint
- [x] Audit log — hash-chained, append-only, `/verify` integrity check
- [x] Threat protection — bot detection, anomaly detection, adaptive rate-limit tuning, IP-allowlist dashboards
- [x] GDPR erasure requests + grace-period purge sweeper
- [x] Data retention — opt-in auto-purge of soft-deleted users (+ preview / run-now)
- [x] Compliance evidence — SOC 2, ISO 27001, GDPR & retention reporting pages

**Developer & platform**

- [x] Webhooks — HMAC-signed, exponential-backoff retry, DLQ
- [x] Transactional outbox + dispatcher
- [x] Auth Hooks / Actions — post-login allow/deny gate (safe-by-default, fail-open)
- [x] SIEM / log streaming — push audit & security events to external log sinks
- [x] AI-agent identity — ephemeral, scoped, revocable agent tokens + delegation (`act` claim) + MCP introspection enforcement
- [x] Verifiable Credentials — W3C JWT-VC issue / verify / revoke + public verification endpoint
- [x] SDKs — first-party TypeScript, React, Next.js, Go and Python clients
- [x] Analytics overview

**Workspace & billing**

- [x] Branding
- [x] Workspace settings + custom domains
- [x] Transactional email templates — per-tenant overrides + preview
- [x] Billing — **internal, multi-currency** plans / subscriptions / invoices (any ISO-4217 currency); **card payments** via Stripe (international) + Razorpay (India) — one-time-per-period checkout, signature-verified webhooks (env-gated, off until keys set)
- [x] Account — profile, security, sessions, data export

**Apps**

- [x] Admin dashboard (Vite + TanStack Router)
- [x] Marketing site (Next.js)
- [x] Hosted login (Next.js)

> End-user docs moved to the standalone multi-product `qeet-docs` site (docs.qeet.in).

Also shipped since this list was first written: **SAML IdP mode** (alongside SP),
**SCIM Groups**, **MFA WebAuthn/step-up**, **OAuth Device grant**, and **crypto
hardening** — Argon2id hashing + ES256/JWKS signing with key rotation. Real SMTP/Twilio
delivery is wired (log-only fallback when unconfigured).

### 🔜 Planned / remaining

- [ ] **CIBA** grant (Client-Initiated Backchannel Auth) — Token Exchange and Device grant already shipped
- [ ] Prebuilt **`<SignIn/>` / `<OrgSwitcher/>`** SDK components (`<UserButton/>` already ships in `@qeetid/react`)
- [ ] **i18n** — retrofit remaining screens, locale-aware emails, non-English catalogs
- [ ] **WCAG 2.2 AA** — expand the accessibility audit across all screens
- [ ] Managed-cloud **infrastructure management** — regions, nodes, scaling
- [ ] **Ops hardening** (not code) — AWS KMS BYOK key setup, OpenID conformance run, email/SMS deliverability (SPF/DKIM/DMARC), RDS automated backups / PITR, external pentest

---

## Tech stack

**Backend**

- Go 1.25, `chi/v5` router, `pgx/v5` PostgreSQL driver
- `golang-jwt/jwt/v5` (ES256 + JWKS, key rotation), `golang.org/x/crypto` (Argon2id, bcrypt-verify fallback)
- In-house TOTP (RFC 6238), HMAC, token codes
- Transactional outbox for event publishing, with DLQ + webhook dispatcher
- Secrets vault — AES-256-GCM at rest via a `KeyProvider` abstraction; AWS KMS (`SECRETS_PROVIDER=aws-kms`) for BYOK

**Frontend**

- React 19 across all apps
- Admin: Vite + TanStack Router + TanStack Query + TanStack Form + TanStack Table
- Web + Login: Next.js 16
- Tailwind 4 + the shared `@qeetrix/*` design system (Base UI / shadcn-style)
- Workspace: pnpm 9.15 + Turborepo 2.9

**SDKs**

- Five first-party SDKs — TypeScript (`@qeetid/sdk`), React (`@qeetid/react`), Next.js (`@qeetid/nextjs`), Go (`sdk/go`), Python (`sdk/python`); all authenticate via `Authorization: ApiKey` + ES256 JWKS verification

**Infrastructure**

- PostgreSQL (Aurora-compatible) — 30+ tables across `tenant`, `user`, `auth`, `rbac`, `audit`, `platform` schemas, all multi-tenant by `tenant_id`
- **Redis** — optional, for distributed (cross-replica) rate limiting; falls back to in-process limits when unset
- Kafka, S3 — planned per [Phase 2 High-Level Architecture](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs/phase-2)

---

## Documentation

- **Implementation status** — [Feature status](#feature-status)
- **Example apps** — [examples/](./examples/) — runnable integrations: a [Next.js app](./examples/nextjs-app) (server-side flow) and a [React SPA](./examples/react-app) (browser-side PKCE)
- **Backend module guide** — [docs/BACKEND.md](./docs/BACKEND.md)
- **Architecture & conventions** — [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)
- **Deploy & operations** — [deploy/RUNBOOK.md](./deploy/RUNBOOK.md)
- **End-user docs** — standalone `qeet-docs` site (docs.qeet.in)
- **API spec** — [api/openapi.yaml](./api/openapi.yaml) — 100% route coverage, guarded in CI (a `chi.Walk` test fails the build on any undocumented route)
- **Postman collection** — [api/postman/qeet-id.postman_collection.json](./api/postman/qeet-id.postman_collection.json)

---

## For AI assistants

- [CLAUDE.md](./CLAUDE.md) — top-level brief for any AI assistant working in this codebase.
- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) — backend conventions new code must follow.

Read [CLAUDE.md](./CLAUDE.md) before making changes if you're a model. Humans see [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Bug reports and feature requests go through GitHub Issues using the templates in [.github/ISSUE_TEMPLATE/](./.github/ISSUE_TEMPLATE/).

## Security

Found a vulnerability? **Please do not open a public issue.** Follow the disclosure process in [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE) © Qeet Group.
