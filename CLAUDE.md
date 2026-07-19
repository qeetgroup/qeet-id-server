# qeet-id — CLAUDE.md

**Qeet ID** — identity platform (Auth0/Okta alternative, passkeys-first), pre-1.0. One Go modular-monolith backend + 3 React frontends (Bun workspaces), **all hoisted to the repo root** (no `backend/`/`frontend/` wrappers).

## Layout (all at repo root)

```
cmd/        Go entrypoints: server, worker, scheduler, migrate, seed
domains/    business logic by bounded context: identity/ access/ federation/ developer/ operations/
platform/   shared infra: api/rest  database/{postgres,migrations,repositories}  cache/ messaging/ events/ observability/ security/ config/
apps/       frontends: console (admin), login, website   (docs/, status/ = placeholders)
api/        contracts: openapi/ (5 split OpenAPI 3.1 specs) · postman/
tsconfig.base.json  shared TS base config (each app's tsconfig extends it)   ·   deploy/ tests/ tools/ bin/
```

## Commands (run from repo root)

**Backend + infra — Makefile (Go only).** The complete target set is exactly:

```bash
make install        # go mod download (backend deps — parallel to `bun install`)
make dev            # go run ./cmd/server  (:4001)
make build test lint
make db-up db-down db-reset          # Postgres :5001 (Docker Compose)
make migrate-up migrate-down         # one migration at a time
make seed seed-reset                 # demo data
make kill                            # free a stuck :4001
```

No `make help`/`dev-*`/`test-*` exist — don't invent targets. Single Go test: `go test ./domains/access/authentication/... -run TestName`.

**Frontend — Bun workspaces:**

```bash
bun install
bun run dev           # all apps
bun run dev:console   # console  :3002  (@qeet-id/console)
bun run dev:website   # website  :3001  (@qeet-id/web)
bun run dev:login     # login    :3003  (@qeet-id/login)
bun run build | lint | format | check | typecheck | test
```

Node **≥24**, Bun **1.3.14**.

## Architecture

**Backend** — single Go module `github.com/qeetgroup/qeet-id` at the root (no `internal/`). Logic under [domains/](domains/) in 5 bounded contexts; shared infra under [platform/](platform/):

- **identity/** — users, organizations (tenant), groups, invitations, verification, domains
- **access/** — authentication, authorization (rbac/rebac/policy), mfa, passkeys, recovery, risk, threat-detection
- **federation/** — oidc, saml, scim, ldap, social
- **developer/** — api-keys, service-accounts, credentials, auth-hooks, webhooks, agents
- **operations/** — audit, analytics, notifications, email-templates, retention, compliance, billing, siem

Only packages with real code exist; planned work lives in [ROADMAP.md](ROADMAP.md), not empty dirs. **Folder name ≠ Go package clause is intentional and legal** (e.g. `domains/access/authentication` = `package auth`, `domains/identity/organizations` = `package tenant`; hyphenated `api-keys`→`apikey`, `service-accounts`→`principal`).

Entrypoint [cmd/server/main.go](cmd/server/main.go); HTTP wiring in [platform/api/rest/router.go](platform/api/rest/router.go) (chi v5). Postgres via pgx v5, **multi-tenant by `tenant_id`** across schemas, with **defense-in-depth Postgres RLS** (migration `0082`): the pool stamps `app.tenant_id`/`app.bypass_rls` per checkout and policies enforce it — but only when the app connects as the non-superuser `qid_app` role (`DB_URL`) with migrations on the owner role (`DB_MIGRATE_URL`); inert under a superuser connection. See `deploy/README.md` §9. Config is envconfig-driven ([platform/config/config.go](platform/config/config.go)); `HTTP_PORT` defaults to `4001`. Transactional outbox + webhook dispatcher (DLQ); the outbox dispatcher publishes domain events to **NATS** when `NATS_URL` is set (else log-only). Hash-chained append-only audit log. API contract = 5 bounded-context OpenAPI 3.1 specs in [api/openapi/](api/openapi/) (no monolith spec).

**Frontend** — [apps/console](apps/console/) (Vite + TanStack Router, admin), [apps/website](apps/website/) + [apps/login](apps/login/) (Next.js). React 19; UI comes from the shared **`@qeetrix/*`** design system (a live dependency). SDKs (`@qeet-id/{sdk,react,nextjs}` + Go/Python) now live in separate `qeet-sdks/` repos under the parent QG folder — no longer in this repo. End-user docs live in the separate `qeet-docs` site.

## Deployment

Single Docker container on EC2 (`ap-south-2`) behind Caddy, Postgres on RDS; migrations auto-apply on startup (`//go:embed`). CI/CD in [.github/workflows/](.github/workflows/) → image to GHCR → SSH `docker compose`. Full runbook: [deploy/README.md](deploy/README.md). Frontends deploy separately.

## Gotchas

- **Migrations** — golang-migrate pairs **0001–0081** in [platform/database/migrations/](platform/database/migrations/) (latest `0081_compliance_evidence`; go **1.25.0**). Never edit an applied migration — add a new pair.
- **Docker** — `Dockerfile` at repo root; build stage `golang:1.26-alpine` (newer than go.mod's `1.25.0`), final image distroless `static-debian12:nonroot`. `.dockerignore` excludes the JS workspace.
- **[apps/website/](apps/website/) has its own `CLAUDE.md`/`AGENTS.md`** — this Next.js version has breaking changes vs. training data; read `node_modules/next/dist/docs/` before writing any Next.js code there.
- **Issues & board** — issues in `qeetgroup/qeet-id` (title `[feat]`/`[fix]`/`[chore]`; body Context / Requirements / Acceptance criteria). Roadmap = org Project **#24**. The **`issue-tracker`** subagent ([.claude/agents/issue-tracker.md](.claude/agents/issue-tracker.md)) creates issues + sets board fields; `gh` needs `project` scope (`gh auth refresh -s project`).
