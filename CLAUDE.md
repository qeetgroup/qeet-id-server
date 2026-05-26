# Claude project guide — qeet-identity

This file briefs Claude (or any other AI assistant) on how to be useful in this codebase. Read it before making changes. Humans, see [README.md](./README.md) and [CONTRIBUTING.md](./CONTRIBUTING.md) instead.

---

## What this repo is

Qeetid is an open-source identity / auth platform — Auth0-style. Monorepo with:

- **`backend/`** — Go 1.22 modular monolith (chi + pgx + PostgreSQL). 19 domain modules under `internal/`. ~80 HTTP endpoints. See [backend/internal/http/router.go](./backend/internal/http/router.go) for the full route table.
- **`frontend/`** — pnpm + Turborepo workspace with three React 19 apps (admin dashboard, marketing site, docs) and a shared shadcn-style UI library.
- **`documents/`** — implementation status mapping every upstream requirement to its place in this codebase. Authoritative for "is feature X done."
- **`backend/api/`** — OpenAPI spec + Postman collection.

Treat this as a **pre-1.0 project**. Roughly 29% of v1.0 must-haves are implemented; see [documents/IMPLEMENTATION-STATUS.md](./documents/IMPLEMENTATION-STATUS.md) and [documents/GAP-ANALYSIS.md](./documents/GAP-ANALYSIS.md) before suggesting new features.

---

## Where things live

**Backend module shape:** each module under `backend/internal/<module>/` typically has `domain.go`, `repository.go`, `service.go`, `http.go` (small modules collapse all of this into a single `<module>.go`). HTTP routes are mounted from `internal/http/router.go`.

**Frontend apps:**
- `frontend/apps/qeetid-admin/` — Vite + TanStack Router (file-based at `src/routes/`)
- `frontend/apps/qeetid-web/` — Next.js (App Router at `src/app/`)
- `frontend/apps/qeetid-docs/` — Next.js + fumadocs, MDX content under `content/docs/`

**Shared UI:** `frontend/packages/qeetid-ui/` — only put primitives here if reused across apps.

**Migrations:** `backend/migrations/*.up.sql` / `*.down.sql`, applied via `golang-migrate`. **Never edit a merged migration** — write a new one with the next number.

**Documents:** `documents/` is the authoritative status. If you add or finish a feature, update [documents/FEATURE-MATRIX.md](./documents/FEATURE-MATRIX.md) and [documents/IMPLEMENTATION-STATUS.md](./documents/IMPLEMENTATION-STATUS.md) in the same PR.

---

## Important conventions

- **Comments:** default to none. Only write a comment when the *why* is non-obvious. Don't restate what the code does or reference the current task ("added for X"). Code structure and commit history carry that already.
- **Error handling:** trust framework guarantees and internal callers. Only validate at system boundaries (HTTP handlers, external API responses). Don't add error checks for situations that can't actually happen.
- **No backward-compat shims** until v1.0. Just change the code.
- **No new abstractions** unless a third concrete caller exists. Three similar lines is better than a premature interface.
- **`Bash` vs editor tools:** prefer dedicated tools (Read, Edit, Write) over `cat`/`sed`/`echo`. Use Bash only for shell-only operations (git, builds, migrations, port checks).

---

## Database conventions

- **Schemas** are domain-grouped: `platform`, `tenant`, `"user"` (quoted, since it's a reserved word), `auth`, `rbac`, `audit`.
- **Tenancy:** every business row carries `tenant_id`. Cross-tenant reads return 403.
- **Soft-delete:** the few tables that support it use `deleted_at TIMESTAMPTZ`.
- **UUIDs everywhere** for primary keys. Generated server-side.
- **Audit:** all mutations should call `audit.Record(ctx, tx, ...)` inside the same transaction — see [backend/internal/audit/audit.go](./backend/internal/audit/audit.go).
- **Outbox:** publish domain events via [backend/internal/platform/outbox/outbox.go](./backend/internal/platform/outbox/outbox.go) (`outbox.Enqueue(ctx, tx, Event{...})`). The dispatcher fans out to webhooks.

---

## Running things

```bash
# Database
make db-up                      # postgres on :5001
make migrate-up                 # apply 21 migrations

# Backend (separate terminal)
make dev-backend                # API on :4000

# Frontend (separate terminal)
make dev                        # backend + 3 frontend apps via Turbo
# Or individually:
make dev-admin                  # :3002
make dev-web                    # :3001
make dev-docs                   # :3003

# Tests / lint
make test
make lint
make typecheck                  # frontend only
```

Default ports — DB :5001, backend API :4000 (or :4001 in Docker), admin :3002, marketing :3001, docs :3003.

---

## Doing changes — quick checklist

| Type of change | What to update |
|---|---|
| New backend module | New directory under `backend/internal/<module>/`, route mount in `internal/http/router.go`, migration under `backend/migrations/`, [openapi.yaml](./backend/api/openapi.yaml), [Postman collection](./backend/api/qeet-identity.postman_collection.json), [documents/IMPLEMENTATION-STATUS.md](./documents/IMPLEMENTATION-STATUS.md), [documents/FEATURE-MATRIX.md](./documents/FEATURE-MATRIX.md). |
| New frontend route | Route file under app's `src/routes/` or `src/app/`, nav entry in [frontend/apps/qeetid-admin/src/config/navigation.tsx](./frontend/apps/qeetid-admin/src/config/navigation.tsx) (admin only), tests. |
| New UI primitive used in two apps | Add to [frontend/packages/qeetid-ui/](./frontend/packages/qeetid-ui/), export from `src/index.ts`. |
| Behaviour change in any handler | Regression test. Pure refactors don't need tests; behaviour changes do. |
| Anything security-relevant | Update [documents/PROTOCOL-STATUS.md](./documents/PROTOCOL-STATUS.md) and call it out in the PR description. |

---

## Don'ts

- ❌ Don't change passwords, tokens, or signing-algorithm code without explicit human approval.
- ❌ Don't downgrade a `RS256`/`ES256` choice to `HS256`.
- ❌ Don't edit a migration that's already in `main`.
- ❌ Don't commit anything matching `.env`, `*.pem`, `*.key`. Root [.gitignore](./.gitignore) helps but verify.
- ❌ Don't reorder columns or drop indexes without an explicit migration.
- ❌ Don't introduce new external dependencies for things stdlib + existing libs already cover.
- ❌ Don't claim a feature is complete in `documents/` unless its happy path is exercised by a test or manual demo recorded in the PR.

---

## Useful queries when investigating

```bash
# List every mounted route
grep -rn "r\.Get\|r\.Post\|r\.Patch\|r\.Put\|r\.Delete" backend/internal/ --include="*.go" | grep -v _test.go

# Find migrations touching a schema
grep -lr "schema_name\." backend/migrations/

# Find every test
find backend -name "*_test.go"

# Check what env vars the backend reads
grep "envconfig:" backend/internal/config/config.go
```

---

## Reference

- Upstream requirements (Phase 1/2/3): [qeetgroup/qeetify · qeetify-reqs](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs)
- Implementation status: [documents/IMPLEMENTATION-STATUS.md](./documents/IMPLEMENTATION-STATUS.md)
- Gap analysis (what's left for v1.0): [documents/GAP-ANALYSIS.md](./documents/GAP-ANALYSIS.md)
- API reference (in progress): [backend/api/openapi.yaml](./backend/api/openapi.yaml)
- Postman: [backend/api/qeet-identity.postman_collection.json](./backend/api/qeet-identity.postman_collection.json)
