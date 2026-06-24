# qeet-id — CLAUDE.md

**Qeet ID** — identity platform (Auth0/Okta alternative, passkeys-first), pre-1.0. Single Go modular-monolith backend + 3 React frontends (pnpm/Turbo), **all hoisted to the repo root** (no `backend/`/`frontend/` wrappers — see the enterprise restructure).

## Layout (everything at the repo root)

```
cmd/        Go entrypoints (server, worker, scheduler, migrate, seed)
domains/    business logic, grouped by bounded context:
            identity/ access/ federation/ developer/ operations/
platform/   shared infra, grouped by concern:
            api/{rest,grpc,openapi}  database/{postgres,migrations,repositories}
            cache/  messaging/  events/  observability/  security/  config/ …
apps/       frontend apps: console (admin), login, website (+ docs/, status/ placeholders)
packages/   shared JS config (qeetid-tsconfig, qeetid-eslint)
sdk/        SDKs: js/{sdk,react,nextjs}, go, python
            platform/database/migrations golang-migrate SQL pairs   api/ openapi/ (5 split specs) + Postman
tests/      Go integration tests        deploy/ base/ + environments/{dev,test,stage,prod} + runbooks        tools/ codegen + scripts + benchmarks
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
make test-api FOLDER=Auth # Postman/Newman against a running backend; scope by folder
make lint typecheck format   ·   make kill   # free stuck dev-server ports
```

All DB/migrate/seed targets now live in the **root** Makefile (they used to be in `backend/Makefile`). Single Go test: `go test ./domains/access/authentication/... -run TestName`.

Frontend uses **pnpm@9.15.4** + Turborepo at the repo root (`@qeetid/*` workspace; globs `apps/* packages/* sdk/js/* examples/*`).

## Architecture

**Backend** — single Go module `github.com/qeetgroup/qeet-id` rooted at the repo root. Business logic lives under [domains/](domains/), grouped into five bounded contexts; shared infra under [platform/](platform/). **Folder names are domain-oriented; Go package clause names are unchanged** (e.g. [domains/access/authentication/](domains/access/authentication/) declares `package auth`, so call sites are `auth.X`).

- **identity/** — `users`, `organizations` (tenant; `+branding`), `groups`, `invitations`, `verification`, `domains` (domain verification)
- **access/** — `authentication` (auth), `authorization/{rbac,rebac,policy,authpolicy}`, `mfa`, `passkeys`, `recovery`, `risk/ipallow`, `threat-detection/{threat,bot}`
- **federation/** — `oidc`, `saml`, `scim`, `ldap`, `social`
- **developer/** — `api-keys`, `service-accounts` (principal), `credentials/{secrets,vc}`, `auth-hooks`, `webhooks`, `agents`
- **operations/** — `audit`, `analytics`, `notifications`, `email-templates`, `retention`, `compliance` (gdpr), `billing`, `siem`

Each context contains only packages that have real code; **planned domains/packages are tracked in [ROADMAP.md](ROADMAP.md)**, not left as empty directories.

Single HTTP entrypoint [cmd/server/main.go](cmd/server/main.go) (worker/scheduler/migrate are sibling entrypoints under [cmd/](cmd/)); HTTP wiring in [platform/api/rest/router.go](platform/api/rest/router.go) (chi v5). Persistence is PostgreSQL via pgx v5, **everything multi-tenant by `tenant_id`** across `tenant`/`user`/`auth`/`rbac`/`audit`/`platform` schemas. Config is envconfig-driven ([platform/config/config.go](platform/config/config.go)); `HTTP_PORT` defaults to `4001`. Event publishing uses a transactional outbox + webhook dispatcher with DLQ; the audit log is hash-chained/append-only. Migrations are golang-migrate SQL files in [platform/database/migrations/](platform/database/migrations/) (apply via `make migrate-up`, never edit an applied migration — add a new pair). API contract: [api/openapi/](api/openapi/) — five bounded-context OpenAPI 3.1 specs, no monolith (merge with `go run ./tools/openapi-split merge`); CI guard reads their union — plus a Postman collection exercised by `make test-api`. Production deploy is EC2 + Docker Compose + AWS RDS — config in [deploy/prod/](deploy/prod/), runbook at [deploy/prod/deploy.md](deploy/prod/deploy.md).

**Frontend** — pnpm/Turbo workspace with three apps ([apps/console](apps/console/) Vite+TanStack Router = `@qeetid/admin`, [apps/website](apps/website/) Next.js = `@qeetid/web`, [apps/login](apps/login/) Next.js hosted login = `@qeetid/login`) sharing `qeetid-tsconfig` / `qeetid-eslint` in [packages/](packages/). The published TS SDKs `@qeetid/{sdk,nextjs,react}` live in [sdk/js/](sdk/js/) (alongside the Go + Python SDKs). React 19 throughout. UI primitives come from the shared **`@qeetrix/*`** design system (wired into all three apps); treat `@qeetrix/*` as a live dependency. (There is no local `qeetid-ui` package, and end-user docs live in the standalone `qeet-docs` site.)

## Gotchas

- **Single Go module at root** — import paths are `github.com/qeetgroup/qeet-id/{domains,platform,cmd}/...` (no more `internal/`). Folder name ≠ package clause is sometimes intentional and legal. The previously-confusing infra leaves were **aligned** so path basename == package clause: `platform/security/tokens` (`package tokens`), `platform/api/rest/httpx` (`package httpx`), `platform/cache/ratelimit` (`package ratelimit`). A few divergences remain by design — e.g. [platform/database/postgres/](platform/database/postgres/) declares `package db`, [platform/observability/logging/](platform/observability/logging/) declares `package logger`, [domains/access/authentication/](domains/access/authentication/) declares `package auth`, [domains/identity/organizations/](domains/identity/organizations/) declares `package tenant`; hyphenated folders (`api-keys`→`apikey`, `service-accounts`→`principal`) can't match a Go identifier at all.
- **Migrations:** golang-migrate pairs **0001–0062** in [platform/database/migrations/](platform/database/migrations/) (latest `0062_credentials.*`; go **1.25.0**). Never edit an applied migration — add a new pair. Path is centralised as `MIGRATIONS_DIR` in the [Makefile](Makefile); the [migrate CLI](cmd/migrate/) + [tools/migration-tools/](tools/migration-tools/) point at the same dir.
- **Docker:** `Dockerfile` is at the repo root — `docker build -t qeet-id:latest .`. The [.dockerignore](.dockerignore) excludes the JS workspace + `deploy/`; migration SQL files are embedded in the binary via `//go:embed` in `platform/database/migrations/runner.go` and run automatically on startup. Prod stack: `deploy/prod/`, dev Postgres: `deploy/dev/`.
- Frontend pins **pnpm@9.15.4** (qeetrix uses 10.32.1) — Corepack handles this from `packageManager`.
- **[apps/website/](apps/website/) has its own `CLAUDE.md`** → `@AGENTS.md`, which warns this Next.js version has breaking changes from training data; read `node_modules/next/dist/docs/` before writing any Next.js code there.
