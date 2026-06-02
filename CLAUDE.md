# qeet-id — CLAUDE.md

**Qeet ID** — identity platform (Auth0/Okta alternative, passkeys-first), pre-1.0. Go modular-monolith backend + 3 React frontends (pnpm/Turbo).

## Commands (`cd qeet-id`)

Root [Makefile](Makefile) orchestrates the Go backend + the pnpm/Turbo frontend. `make help` lists everything.

```bash
make install              # go mod tidy + pnpm install
make db-up && make migrate-up   # Postgres on :5001 (Docker) + apply migrations
make dev                  # backend (:4000) + all 3 frontend apps in parallel
make dev-backend          # backend only (:4000 local; :4001 under docker compose)
make dev-admin / dev-web / dev-docs   # one frontend app (:3002 / :3001 / :3003)
make test                 # go test ./...  +  frontend turbo test
make test-backend         # Go only
make test-api FOLDER=Auth # Postman/Newman against a running backend; scope by folder
make lint typecheck format
make kill                 # free stuck dev-server ports
```

Backend-only targets live in [backend/Makefile](backend/Makefile): `make run`, `make build`, `make test`, `make migrate-up/down/force V=<n>`, `make db-reset` (psql), `make db-wipe` (golang-migrate). Single Go test: `cd backend && go test ./internal/auth/... -run TestName`.

Frontend uses **pnpm@9.15.4** + Turborepo from [frontend/](frontend/) (`@qeetid/*` workspace).

## Architecture

**Backend** — Go modular monolith under [backend/internal/](backend/internal/), one package per domain (`auth`, `oidc`, `rbac`, `mfa`, `passkey`, `social`, `webhook`, `audit`, `gdpr`, `tenant`, `user`, `apikey`, `platform`, …). Single entrypoint [cmd/server/main.go](backend/cmd/server/main.go); HTTP wiring in [internal/http/router.go](backend/internal/http/router.go) (chi v5). Persistence is PostgreSQL via pgx v5, **everything multi-tenant by `tenant_id`** across `tenant`/`user`/`auth`/`rbac`/`audit`/`platform` schemas. Config is envconfig-driven ([internal/config/config.go](backend/internal/config/config.go)); `HTTP_PORT` defaults to `4000`. Event publishing uses a transactional outbox + webhook dispatcher with DLQ; the audit log is hash-chained/append-only. Migrations are golang-migrate SQL files in [backend/migrations/](backend/migrations/) (apply via `make migrate-up`, never edit an applied migration — add a new pair). API contract: [backend/api/openapi.yaml](backend/api/) + a Postman collection exercised by `make test-api`.

**Frontend** — pnpm/Turbo workspace with three apps (`qeetid-admin` Vite+TanStack Router, `qeetid-web` Next.js, `qeetid-docs` Next.js+fumadocs) sharing `qeetid-ui` / `qeetid-tsconfig` / `qeetid-eslint` packages. React 19 throughout. **`@qeetrix/ui` is already wired into both `qeetid-admin` and `qeetid-web`** — 85 and 29 source files respectively import from it (verified 2026-06-02); treat `@qeetrix/*` as a live dependency.

## Gotchas

- **This repo's README overstates it.** It references a `.claude/` rules/skills/commands layer, a `CLAUDE.md`, and a `documents/` folder — **none exist** in the checkout. It also says "25 migrations / Go 1.22"; the actual repo has **40 migrations** (0001–0040) and **go 1.25.0**. Trust the files over the README.
- Frontend pins **pnpm@9.15.4** (qeetrix uses 10.32.1) — Corepack handles this from `packageManager`.
- **[frontend/apps/qeetid-web/](frontend/apps/qeetid-web/) has its own `CLAUDE.md`** → it `@AGENTS.md`, which warns this Next.js version has breaking changes from training data; read `node_modules/next/dist/docs/` before writing any Next.js code there.
