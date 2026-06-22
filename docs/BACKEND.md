# qeet-id backend

Go modular monolith for the Qeet ID identity platform. Single Go service,
single Postgres database with one schema per bounded context. Each context
ships an outbox so it can be peeled off into its own service later without
rewriting business logic.

## Quick start

```bash
make db-up                         # Postgres on :5001 (Docker)
cp .env.example .env               # if you don't have a .env yet
make migrate-up                    # apply DB migrations (needs golang-migrate CLI)
make seed-reset                    # fill the DB with demo data (see below)
make run                           # start the API on :4001
```

Then open the admin UI and log in (see credentials under **Seed demo data**).

## Seed demo data

The fastest way to see the app with real content. It creates two workspaces,
users, roles, groups, API keys, webhooks, SSO providers, branding, a policy,
and some login/audit history — using the app's own code, so logins actually
work and the audit log is properly hash-chained.

```bash
make seed-reset   # wipe (dev only) + load a clean demo dataset
make seed         # add demo data without wiping (use seed-reset if it already exists)
```

**Every seeded account uses the same password: `Password123!`**

| Email | Workspace | Role | Notes |
| --- | --- | --- | --- |
| `owner@acme.test` | Acme + Globex | owner | owns both — use it to try the workspace switcher |
| `alice@acme.test` | Acme | admin | |
| `bob@acme.test` | Acme | member | |
| `carol@acme.test` | Acme | member | |
| `dave@acme.test` | Acme | member | |
| `erin@globex.test` | Globex | member | |

Workspaces: **Acme Inc** (`acme`) and **Globex Corp** (`globex`).

The seed also prints two one-time API-key tokens (`qk_…`) in its output if you
want to test API-key auth (the plaintext secret is only shown once).

## How signup / workspaces work

- **Signup creates no tenant.** A new user is a tenant-less identity and lands
  on a "create your first workspace" screen.
- **Creating a workspace makes you its owner** (owner role + all permissions)
  and switches you into it. A user can belong to many workspaces; membership is
  expressed by `rbac.user_roles`, and the Users list shows a workspace's members.
- **Switching workspaces** mints a fresh token scoped to that tenant
  (`POST /v1/auth/switch-tenant`). Login is `email` + `password` only.

## Layout

```
cmd/
  server/               # main.go — process lifecycle; buildDeps() wires modules
  seed/                 # `make seed` demo-data loader
platform/               # cross-cutting infrastructure
  config/               # envconfig (DB, JWT, APP_BASE_URL, …)
  db/                   # pgx pool
  errs/                 # error vocabulary
  pgxerr/               # map Postgres errors -> domain errors (IsUnique, …)
  dbutil/               # shared repo helpers: JSONB decode + UPDATE builder
  httpx/                # response, auth, principal, RequireTenant/RequireUser
  paging/               # opaque keyset cursors
  worker/               # Supervisor: start/stop background workers
  logger/ outbox/ password/ tokens/ ratelimit/ notifier/ codes/ health/ totp/ hibp/
  metrics/ tracing/ buildinfo/
  sqlcgen/              # GENERATED sqlc pilot (unused template — see sqlc/)
  http/                 # chi router that mounts every handler
domains/                # business logic, grouped by bounded context
  identity/             # users, organizations(+branding), groups, invitations, verification, domains
  access/               # authentication(auth), authorization/{rbac,rebac,policy,authpolicy},
                        #   mfa, passkeys, recovery, risk/ipallow, threat-detection/{threat,bot}
  federation/           # oidc, saml, scim, ldap, social
  developer/            # api-keys, service-accounts(principal), credentials/{secrets,vc},
                        #   auth-hooks, webhooks, agents
  operations/           # audit, analytics, notifications, email-templates, retention,
                        #   compliance(gdpr), billing, siem
migrations/             # sql, paired up/down
sqlc/                   # sqlc.yaml inputs (schema snapshot + queries)
tests/integration/      # testcontainers-backed integration tests
api/openapi.yaml        # per-context API spec
```

## Common commands

| Command | What it does |
| --- | --- |
| `make run` | Start the API (`:4001`) |
| `make seed-reset` / `make seed` | Load demo data (wipe-first / additive) |
| `make migrate-up` / `migrate-down` | Apply / roll back DB migrations |
| `make test` | Unit tests (no Docker needed) |
| `make test-integration` | Integration tests against a throwaway Postgres (needs Docker) |
| `make build` `lint` `tidy` | Build binary / lint / `go mod tidy` |
| `make sqlc-generate` `sqlc-schema` | Regenerate the sqlc pilot / refresh its schema snapshot |
| `make db-up` / `db-down` | Start / stop the Postgres container (Docker) |
| `make db-psql` | Open a psql shell in the DB container |

## Testing

- `make test` — fast unit tests, no external services.
- `make test-integration` — spins up an ephemeral Postgres via
  [testcontainers], applies the real migrations, and exercises full flows
  (signup → login → refresh/theft, create-workspace-with-owner, tenant
  isolation, audited group changes). Gated behind the `integration` build tag,
  so plain `make test` stays Docker-free. Skips cleanly if Docker is absent.

[testcontainers]: https://golang.testcontainers.org/

## sqlc (optional, not wired in)

`platform/sqlcgen/` is a **generated template** showing type-safe,
compile-checked queries. Nothing imports it yet — repositories still use
hand-written SQL. Adopt it incrementally with `make sqlc-generate` if/when
desired; run `make sqlc-schema` after adding migrations.

## Module rules (so a context can be split out later)

1. Its own Postgres schema. No cross-schema JOINs.
2. Its own outbox topic.
3. No imports of another module's internals — wire through interfaces (see the
   `tokenIssuer` interface used by tenant/invite/recovery).
4. Its own OpenAPI spec under `api/` as the surface grows.
5. Every mutation runs in one transaction that writes the business row, the
   audit row, and (where relevant) the outbox row together. The service owns
   that transaction; handlers stay thin.
6. No shared mutable state.
