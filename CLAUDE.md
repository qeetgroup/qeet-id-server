# qeet-id — CLAUDE.md

**Qeet ID** — identity platform (Auth0/Okta alternative, passkeys-first), pre-1.0. Single Go modular-monolith backend + 3 React frontends (pnpm/Turbo), **all hoisted to the repo root** (no `backend/`/`frontend/` wrappers — see the enterprise restructure).

## Layout (everything at the repo root)

```
cmd/        Go entrypoints (server, worker, scheduler, migrate, seed)
domains/    business logic, grouped by bounded context:
            identity/ access/ federation/ developer/ operations/
platform/   shared infra, grouped by concern:
            api/rest  database/{postgres,migrations,repositories}
            cache/  messaging/  events/  observability/  security/  config/ …
apps/       frontend apps: console (admin), login, website (+ docs/, status/ placeholder dirs)
packages/   shared JS config: qeetid-tsconfig/ (pkg @qeet-id/tsconfig).
            ESLint is the root eslint.config.mjs flat config — NOT a package.
sdk/        SDKs: js/{sdk,react,nextjs}, go, python
api/        API contracts at the repo ROOT (not under platform/):
            openapi/ (5 split OpenAPI 3.1 specs + README) · postman/ (collection)
deploy/     EC2 + Caddy + RDS deploy runbook (deploy/README.md)
examples/   sample SDK apps: react-app, nextjs-app
tests/      Go integration tests   ·   tools/ codegen + scripts + benchmarks   ·   bin/ build output
```

## Commands (`cd qeet-id`, run from the root)

Two interfaces: a small **Makefile** drives the Go backend + Docker infra; **pnpm/Turbo** scripts drive the frontend. There is **no `make help`/`make install`/`make dev-*`/`make test-*`** — the *complete* set of real Makefile targets is exactly:

```bash
# Backend + infra (Makefile — Go only)
make dev                  # backend only: go run ./cmd/server  (:4001)
make build                # go build -o bin/qeet-id ./cmd/server  (Go binary only)
make test                 # go test ./...
make lint                 # go vet
make db-up / db-down / db-reset      # Postgres :5001 via Docker Compose
make migrate-up / migrate-down       # apply / roll back one migration
make seed / seed-reset               # demo data
make kill                            # free a stuck backend on :4001
```

```bash
# Frontend (pnpm + Turborepo, from the repo root)
pnpm install
pnpm dev                  # all apps in parallel
pnpm dev:admin            # console only  (:3002, @qeet-id/console)
pnpm dev:web              # website only  (:3001, @qeet-id/web)
pnpm dev:login            # hosted login  (:3004, @qeet-id/login)
pnpm build | lint | format | check | typecheck | test   # Turbo across the workspace
```

Single Go test: `go test ./domains/access/authentication/... -run TestName`. Frontend pins **pnpm@9.15.4** + Turborepo at the repo root (`@qeet-id/*` workspace; globs `apps/* packages/* sdk/js/* examples/*`) and requires **Node ≥24** (`.nvmrc` pins `24`; Corepack handles pnpm). Postman/Newman API tests live under `api/postman/` (run against a running backend).

## Architecture

**Backend** — single Go module `github.com/qeetgroup/qeet-id` rooted at the repo root. Business logic lives under [domains/](domains/), grouped into five bounded contexts; shared infra under [platform/](platform/). **Folder names are domain-oriented; Go package clause names are unchanged** (e.g. [domains/access/authentication/](domains/access/authentication/) declares `package auth`, so call sites are `auth.X`).

- **identity/** — `users`, `organizations` (tenant; `+branding`), `groups`, `invitations`, `verification`, `domains` (domain verification)
- **access/** — `authentication` (auth), `authorization/{rbac,rebac,policy,authpolicy}`, `mfa`, `passkeys`, `recovery`, `risk/ipallow`, `threat-detection/{threat,bot}`
- **federation/** — `oidc`, `saml`, `scim`, `ldap`, `social`
- **developer/** — `api-keys`, `service-accounts` (principal), `credentials/{secrets,vc}`, `auth-hooks`, `webhooks`, `agents`
- **operations/** — `audit`, `analytics`, `notifications`, `email-templates`, `retention`, `compliance` (gdpr), `billing`, `siem`

Each context contains only packages that have real code; **planned domains/packages are tracked in [ROADMAP.md](ROADMAP.md)**, not left as empty directories.

Single HTTP entrypoint [cmd/server/main.go](cmd/server/main.go) (worker/scheduler/migrate are sibling entrypoints under [cmd/](cmd/)); HTTP wiring in [platform/api/rest/router.go](platform/api/rest/router.go) (chi v5). Persistence is PostgreSQL via pgx v5, **everything multi-tenant by `tenant_id`** across `tenant`/`user`/`auth`/`rbac`/`audit`/`platform` schemas. Config is envconfig-driven ([platform/config/config.go](platform/config/config.go)); `HTTP_PORT` defaults to `4001`. Event publishing uses a transactional outbox + webhook dispatcher with DLQ; the audit log is hash-chained/append-only. Migrations are golang-migrate SQL files in [platform/database/migrations/](platform/database/migrations/) (apply via `make migrate-up`, never edit an applied migration — add a new pair). API contract: [api/openapi/](api/openapi/) — five bounded-context OpenAPI 3.1 specs, no monolith (merge with `go run ./tools/openapi-split merge`); CI guard reads their union — plus a Postman collection under [api/postman/](api/postman/).

**Frontend** — pnpm/Turbo workspace with three apps ([apps/console](apps/console/) Vite+TanStack Router = `@qeet-id/console` (admin UI), [apps/website](apps/website/) Next.js = `@qeet-id/web`, [apps/login](apps/login/) Next.js hosted login = `@qeet-id/login`); `apps/docs`/`apps/status` are placeholder dirs. They share `@qeet-id/tsconfig` ([packages/qeetid-tsconfig/](packages/qeetid-tsconfig/)); ESLint is the root `eslint.config.mjs` flat config (there is no shared eslint package). The published TS SDKs `@qeet-id/{sdk,react,nextjs}` live in [sdk/js/](sdk/js/) (alongside the Go + Python SDKs). React 19 throughout. UI primitives come from the shared **`@qeetrix/*`** design system (wired into all three apps); treat `@qeetrix/*` as a live dependency. (There is no local `qeetid-ui` package, and end-user docs live in the standalone `qeet-docs` site.)

## Deployment

The backend ships as a **single Docker container** on EC2 (`ap-south-2`, Hyderabad) behind **Caddy** (automatic HTTPS), with **Postgres on RDS**; migrations auto-apply on startup (`//go:embed`). CI/CD lives in [.github/workflows/](.github/workflows/) (`ci.yml`, `codeql.yml`, `deploy.yml`) → image pushed to **GHCR** → deployed via SSH + `docker compose`. Full runbook + the minimal compose/env setup are in [deploy/README.md](deploy/README.md). Frontends deploy separately (not covered here).

## Gotchas

- **Single Go module at root** — import paths are `github.com/qeetgroup/qeet-id/{domains,platform,cmd}/...` (no more `internal/`). Folder name ≠ package clause is sometimes intentional and legal. The previously-confusing infra leaves were **aligned** so path basename == package clause: `platform/security/tokens` (`package tokens`), `platform/api/rest/httpx` (`package httpx`), `platform/cache/ratelimit` (`package ratelimit`). A few divergences remain by design — e.g. [platform/database/postgres/](platform/database/postgres/) declares `package db`, [platform/observability/logging/](platform/observability/logging/) declares `package logger`, [domains/access/authentication/](domains/access/authentication/) declares `package auth`, [domains/identity/organizations/](domains/identity/organizations/) declares `package tenant`; hyphenated folders (`api-keys`→`apikey`, `service-accounts`→`principal`) can't match a Go identifier at all.
- **Migrations:** golang-migrate pairs **0001–0062** in [platform/database/migrations/](platform/database/migrations/) (latest `0062_credentials.*`; go **1.25.0**). Never edit an applied migration — add a new pair. Path is centralised as `MIGRATIONS_DIR` in the [Makefile](Makefile); the [migrate CLI](cmd/migrate/) + [tools/migration-tools/](tools/migration-tools/) point at the same dir.
- **Docker:** `Dockerfile` is at the repo root — `docker build -t qeet-id:latest .`. Build stage is `golang:1.26-alpine` (newer than go.mod's `1.25.0`); final image is distroless `gcr.io/distroless/static-debian12:nonroot`. The [.dockerignore](.dockerignore) excludes the JS workspace; migration SQL files are embedded in the binary via `//go:embed` in `platform/database/migrations/runner.go` and run automatically on startup.
- **Node ≥24 required** for the frontend (`package.json` `engines` + `.nvmrc` pins `24`). Frontend pins **pnpm@9.15.4** (qeetrix uses 10.32.1) — Corepack handles this from `packageManager`.
- **[apps/website/](apps/website/) has its own `CLAUDE.md`** → `@AGENTS.md`, which warns this Next.js version has breaking changes from training data; read `node_modules/next/dist/docs/` before writing any Next.js code there.
