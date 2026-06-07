# qeet-id — CLAUDE.md

**Qeet ID** — identity platform (Auth0/Okta alternative, passkeys-first), pre-1.0. Go modular-monolith backend + 3 React frontends (pnpm/Turbo).

## Commands (`cd qeet-id`)

Root [Makefile](Makefile) orchestrates the Go backend + the pnpm/Turbo frontend. `make help` lists everything.

```bash
make install              # go mod tidy + pnpm install
make -C backend db-up migrate-up   # Postgres :5001 (Docker) + migrations (DB targets are backend-only)
make dev                  # backend (:4000) + all 3 frontend apps in parallel
make dev-backend          # backend only (:4000)
make dev-admin / dev-web / dev-login   # one frontend app (:3002 / :3001 / :3004)
make test                 # go test ./...  +  frontend turbo test
make test-backend         # Go only
make test-api FOLDER=Auth # Postman/Newman against a running backend; scope by folder
make lint typecheck format
make kill                 # free stuck dev-server ports
```

All **DB / migrate / seed targets live ONLY in [backend/Makefile](backend/Makefile)** now (the root Makefile no longer wraps them): `make run`, `make build`, `make test`, `make db-up`/`db-down` (Postgres container), `make migrate-up/down/force V=<n>`, `make db-reset` (psql) / `make db-wipe` (golang-migrate), `make seed`/`seed-reset`. Run them from `backend/`, or without cd: `make -C backend <target>`. Single Go test: `cd backend && go test ./internal/auth/... -run TestName`.

Frontend uses **pnpm@9.15.4** + Turborepo from [frontend/](frontend/) (`@qeetid/*` workspace).

## Architecture

**Backend** — Go modular monolith under [backend/internal/](backend/internal/), one package per domain (`auth`, `oidc`, `rbac`, `mfa`, `passkey`, `social`, `webhook`, `audit`, `gdpr`, `tenant`, `user`, `apikey`, `platform`, …). Single entrypoint [cmd/server/main.go](backend/cmd/server/main.go); HTTP wiring in [internal/http/router.go](backend/internal/http/router.go) (chi v5). Persistence is PostgreSQL via pgx v5, **everything multi-tenant by `tenant_id`** across `tenant`/`user`/`auth`/`rbac`/`audit`/`platform` schemas. Config is envconfig-driven ([internal/config/config.go](backend/internal/config/config.go)); `HTTP_PORT` defaults to `4001`. Event publishing uses a transactional outbox + webhook dispatcher with DLQ; the audit log is hash-chained/append-only. Migrations are golang-migrate SQL files in [backend/migrations/](backend/migrations/) (apply via `make migrate-up`, never edit an applied migration — add a new pair). API contract: [backend/api/openapi.yaml](backend/api/) + a Postman collection exercised by `make test-api`.

**Frontend** — pnpm/Turbo workspace with three apps (`qeetid-admin` Vite+TanStack Router, `qeetid-web` Next.js, `qeetid-login` Next.js hosted login) sharing `qeetid-tsconfig` / `qeetid-eslint` packages, plus the `qeetid-{sdk,nextjs,react}` TypeScript SDKs. React 19 throughout. UI primitives come from the shared **`@qeetrix/*`** design system (wired into admin + web + login); treat `@qeetrix/*` as a live dependency. (There is no local `qeetid-ui` package, and end-user docs moved to the standalone `qeet-docs` site.)

## Gotchas

- **Migrations:** golang-migrate pairs **0001–0048** in `backend/migrations/` (go **1.25.0**). Never edit an applied migration — add a new pair.
- **No `.claude/` or `documents/` layer exists** in this checkout (an older README claimed one; the README has since been corrected). Trust the files over any stale doc.
- Frontend pins **pnpm@9.15.4** (qeetrix uses 10.32.1) — Corepack handles this from `packageManager`.
- **[frontend/apps/qeetid-web/](frontend/apps/qeetid-web/) has its own `CLAUDE.md`** → it `@AGENTS.md`, which warns this Next.js version has breaking changes from training data; read `node_modules/next/dist/docs/` before writing any Next.js code there.
