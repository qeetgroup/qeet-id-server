# qeet-id — CLAUDE.md

**Qeet ID** — identity platform (Auth0/Okta alternative, passkeys-first), pre-1.0. This repo (`qeet-id-server`, module `github.com/qeetgroup/qeet-id-server`) is the **Go modular-monolith backend**. The three React frontends now live in their own repos: console → `qeet-consoles/qeet-id-console`, marketing site → `qeet-websites/qeet-id-website`, hosted login → `qeet-hosted/qeet-id-login`.

## Layout

Single Go module `github.com/qeetgroup/qeet-id-server`; **all application code lives under `internal/`** (thin entrypoints under `cmd/`).

```
cmd/          Go entrypoints: api, worker, scheduler, migrate, seed
internal/
  bootstrap/  composition root — the ONLY package that wires everything (chi router + permissions live here)
  access/ identity/ federation/ developer/ operations/   5 bounded contexts (business logic)
  platform/   PURE infra: http/{httpx,codes,errs,paging}  database/{postgres,migrations,rlsctx}
              cache/ config/ crypto/ events/ messaging/ observability/ ai/ jobs/
api/          contracts: openapi/ (5 split OpenAPI 3.1 specs) · postman/
tests/ tools/   (deploy manifests + CD → qeet-deploy/qeet-id-deploy)
```

## Commands (run from repo root)

**Backend + infra — Makefile (Go only).** The complete target set is exactly:

```bash
make install        # go mod download (backend deps)
make dev            # go run ./cmd/api  (:4001)
make build test lint
make db-up db-down db-reset          # Postgres :5001 (Docker Compose)
make migrate-up migrate-down         # one migration at a time
make seed seed-reset                 # demo data
make kill                            # free a stuck :4001
```

No `make help`/`dev-*`/`test-*` exist — don't invent targets. Single Go test: `go test ./internal/access/authentication/... -run TestName`.

**Frontends — not in this repo.** Each is its own repo (bun): hosted login → `qeet-hosted/qeet-id-login` (:3003),
admin console → `qeet-consoles/qeet-id-console` (:3002), marketing site → `qeet-websites/qeet-id-website` (:3001).

## Architecture

**Backend** — a single Go module `github.com/qeetgroup/qeet-id-server`; **all code lives under [internal/](internal/)**. The 5 bounded contexts sit directly under `internal/`, pure infra under [internal/platform/](internal/platform/), and the composition root under [internal/bootstrap/](internal/bootstrap/):

- **internal/access/** — authentication, authorization (rbac/rebac/policy), mfa, passkeys, recovery, risk, threat
- **internal/identity/** — users, tenant, groups, invitations, verification, domainverify
- **internal/federation/** — oidc, saml, scim, ldap, social
- **internal/developer/** — api-keys, principal, credentials, auth-hooks, webhooks, agents
- **internal/operations/** — audit, analytics, notifications, email, retention, gdpr, billing, siem
- **internal/platform/** — pure infra only: http, database, cache, config, crypto, events, messaging, observability, ai, jobs

**Dependency rule** (the whole point of the layout): `internal/platform/*` is **pure infra** — it imports no bounded context, no `cmd/*`, and not `internal/bootstrap`. The 5 contexts may import `internal/platform/*` but never `cmd/*` or `internal/bootstrap`. **Only `internal/bootstrap`** — the composition root — imports and wires everything together (the chi router + permission table live there); `cmd/*` entrypoints just call into it.

Only packages with real code exist; planned work lives in [ROADMAP.md](ROADMAP.md), not empty dirs. The former semantic folder≠package mismatches were aligned to **folder == package** (`organizations`→`tenant`, `compliance`→`gdpr`, `identity/domains`→`domainverify`, `service-accounts`→`principal`, `email`→`package email`). **A few folders still differ where the package uses a shorter idiomatic name — intentional and legal** (e.g. `internal/access/authentication` = `package auth`, `internal/developer/api-keys` = `package apikey`, `internal/platform/jobs` = `package worker`).

Entrypoint [cmd/api/main.go](cmd/api/main.go); HTTP wiring in [internal/bootstrap/router.go](internal/bootstrap/router.go) (chi v5). Postgres via pgx v5, **multi-tenant by `tenant_id`** across schemas, with **defense-in-depth Postgres RLS** (migration `0082`): the pool stamps `app.tenant_id`/`app.bypass_rls` per checkout and policies enforce it — but only when the app connects as the non-superuser `qid_app` role (`DB_URL`) with migrations on the owner role (`DB_MIGRATE_URL`); inert under a superuser connection. See `qeet-deploy/qeet-id-deploy/README.md` §9. Config is envconfig-driven ([internal/platform/config/config.go](internal/platform/config/config.go)); `HTTP_PORT` defaults to `4001`. Transactional outbox + webhook dispatcher (DLQ); the outbox dispatcher publishes domain events to **NATS** when `NATS_URL` is set (else log-only). Hash-chained append-only audit log. API contract = 5 bounded-context OpenAPI 3.1 specs in [api/openapi/](api/openapi/) (no monolith spec).

**Frontends (all separate repos now)** — hosted login → `qeet-hosted/qeet-id-login` (Next.js), admin console → `qeet-consoles/qeet-id-console` (Vite + TanStack), marketing site → `qeet-websites/qeet-id-website` (Next.js); all on the shared **`@qeetrix/*`** design system. SDKs (`@qeet-id/{sdk,react,nextjs}` + Go/Python) live in `qeet-sdks/`. End-user docs live in the separate `qeet-docs` site.

## Deployment

Single Docker container on EC2 (`ap-south-2`) behind Caddy, Postgres on RDS; migrations auto-apply on startup (`//go:embed`). **Deploy (build image → GHCR + SSH rollout) and all manifests (compose/Caddy/Helm/Terraform) live in the separate `qeet-deploy/qeet-id-deploy` repo** (full runbook there). Frontends deploy separately.

## Gotchas

- **Migrations** — golang-migrate pairs **0001–0081** in [internal/platform/database/migrations/](internal/platform/database/migrations/) (latest `0081_compliance_evidence`; go **1.25.0**). Never edit an applied migration — add a new pair.
- **Docker** — `Dockerfile` at repo root; build stage `golang:1.26-alpine` (newer than go.mod's `1.25.0`), final image distroless `static-debian12:nonroot`. `.dockerignore` excludes the JS workspace.- **Issues & board** — issues in `qeetgroup/qeet-id-server` (title `[feat]`/`[fix]`/`[chore]`; body Context / Requirements / Acceptance criteria). Roadmap = org Project **#24**. The **`issue-tracker`** subagent ([.claude/agents/issue-tracker.md](.claude/agents/issue-tracker.md)) creates issues + sets board fields; `gh` needs `project` scope (`gh auth refresh -s project`).
