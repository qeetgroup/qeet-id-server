# qeet-id — CLAUDE.md

**Qeet ID** — identity platform (Auth0/Okta alternative, passkeys-first), pre-1.0. Single Go modular-monolith backend + 3 React frontends (pnpm/Turbo), **all hoisted to the repo root** (no `backend/`/`frontend/` wrappers — see the enterprise restructure).

## Layout (everything at the repo root)

```
cmd/        Go entrypoints (server, seed)
domains/    business logic, grouped by bounded context:
            identity/ access/ federation/ developer/ operations/
platform/   shared infra (db, tokens, httpx, logger, http router/wiring, config, …)
apps/       frontend apps: console (admin), login, website (+ docs/, status/ placeholders)
packages/   shared JS config (qeetid-tsconfig, qeetid-eslint)
sdk/        SDKs: js/{sdk,react,nextjs}, go, python
migrations/ golang-migrate SQL pairs   api/ openapi.yaml + Postman   sqlc/ codegen inputs
tests/      Go integration tests        deploy/ Helm + compose + observability
```

## Commands (`cd qeet-id`, run from the root)

Single root [Makefile](Makefile) orchestrates the Go module + the pnpm/Turbo workspace. `make help` lists everything.

```bash
make install              # go mod tidy + pnpm install
make db-up migrate-up     # Postgres :5001 (Docker) + migrations
make dev                  # backend (:4001) + all 3 frontend apps in parallel
make dev-backend          # backend only (:4001)  ·  go run ./cmd/server
make dev-admin / dev-web / dev-login   # one frontend app (:3002 / :3001 / :3004)
make build                # go build ./cmd/server (ldflags-stamped) + pnpm build
make test                 # go test ./...  +  frontend turbo test
make test-backend         # Go only   ·   make test-integration (testcontainers, needs Docker)
make seed / seed-reset    # demo data
make migrate-up/down/force V=<n> / migrate-down-all   ·   db-up/db-down/db-reset/db-wipe/db-psql
make sqlc-generate / sqlc-schema
make test-api FOLDER=Auth # Postman/Newman against a running backend; scope by folder
make lint typecheck format   ·   make kill   # free stuck dev-server ports
```

All DB/migrate/seed/sqlc targets now live in the **root** Makefile (they used to be in `backend/Makefile`). Single Go test: `go test ./domains/access/authentication/... -run TestName`.

Frontend uses **pnpm@9.15.4** + Turborepo at the repo root (`@qeetid/*` workspace; globs `apps/* packages/* sdk/js/* examples/*`).

## Architecture

**Backend** — single Go module `github.com/qeetgroup/qeet-id` rooted at the repo root. Business logic lives under [domains/](domains/), grouped into five bounded contexts; shared infra under [platform/](platform/). **Folder names are domain-oriented; Go package clause names are unchanged** (e.g. [domains/access/authentication/](domains/access/authentication/) declares `package auth`, so call sites are `auth.X`).

- **identity/** — `users`, `organizations` (tenant; `+branding`), `groups`, `invitations`, `verification`, `domains` (domain verification) [+ `memberships`/`profiles` placeholders]
- **access/** — `authentication` (auth), `authorization/{rbac,rebac,policy,authpolicy}`, `mfa`, `passkeys`, `recovery`, `risk/ipallow`, `threat-detection/{threat,bot}` [+ `sessions`/`passwords`/`devices`/`trusted-devices`/`lockout` placeholders]
- **federation/** — `oidc`, `saml`, `scim`, `ldap`, `social` [+ `oauth2`/`provisioning` placeholders]
- **developer/** — `api-keys`, `service-accounts` (principal), `credentials/{secrets,vc}`, `auth-hooks`, `webhooks`, `agents` [+ `bots`/`integrations` placeholders]
- **operations/** — `audit`, `analytics`, `notifications`, `email-templates`, `retention`, `compliance` (gdpr), `billing`, `siem` [+ `subscriptions`/`invoices`/`exports`/`log-streaming` placeholders]

Single entrypoint [cmd/server/main.go](cmd/server/main.go); HTTP wiring in [platform/http/router.go](platform/http/router.go) (chi v5). Persistence is PostgreSQL via pgx v5, **everything multi-tenant by `tenant_id`** across `tenant`/`user`/`auth`/`rbac`/`audit`/`platform` schemas. Config is envconfig-driven ([platform/config/config.go](platform/config/config.go)); `HTTP_PORT` defaults to `4001`. Event publishing uses a transactional outbox + webhook dispatcher with DLQ; the audit log is hash-chained/append-only. Migrations are golang-migrate SQL files in [migrations/](migrations/) (apply via `make migrate-up`, never edit an applied migration — add a new pair). API contract: [api/openapi.yaml](api/) + a Postman collection exercised by `make test-api`. Production deploy layer (Helm, `compose`, runbook, observability) lives in [deploy/](deploy/).

**Frontend** — pnpm/Turbo workspace with three apps ([apps/console](apps/console/) Vite+TanStack Router = `@qeetid/admin`, [apps/website](apps/website/) Next.js = `@qeetid/web`, [apps/login](apps/login/) Next.js hosted login = `@qeetid/login`) sharing `qeetid-tsconfig` / `qeetid-eslint` in [packages/](packages/). The published TS SDKs `@qeetid/{sdk,nextjs,react}` live in [sdk/js/](sdk/js/) (alongside the Go + Python SDKs). React 19 throughout. UI primitives come from the shared **`@qeetrix/*`** design system (wired into all three apps); treat `@qeetrix/*` as a live dependency. (There is no local `qeetid-ui` package, and end-user docs live in the standalone `qeet-docs` site.)

## Gotchas

- **Single Go module at root** — import paths are `github.com/qeetgroup/qeet-id/{domains,platform,cmd}/...` (no more `internal/`). Folder name ≠ package clause is intentional and legal.
- **Migrations:** golang-migrate pairs **0001–0062** in [migrations/](migrations/) (latest `0062_credentials.*`; go **1.25.0**). Never edit an applied migration — add a new pair.
- **Docker build context is the repo root** (single Go module). The root [.dockerignore](.dockerignore) excludes the JS workspace; keep `migrations/` un-ignored (the shared [Dockerfile.migrate](Dockerfile.migrate) copies it).
- **Two known pre-existing test failures** in [platform/httpx](platform/httpx/) (`TestCSRF_RefererFallback`, `TestCSRF_NormaliseOriginsTrimsSlashAndCases`) — internally inconsistent fixtures, unrelated to the restructure (byte-identical to before). Fix the fixtures separately.
- Frontend pins **pnpm@9.15.4** (qeetrix uses 10.32.1) — Corepack handles this from `packageManager`.
- **[apps/website/](apps/website/) has its own `CLAUDE.md`** → `@AGENTS.md`, which warns this Next.js version has breaking changes from training data; read `node_modules/next/dist/docs/` before writing any Next.js code there.
