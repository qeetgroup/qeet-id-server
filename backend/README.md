# qeet-identity backend

Go modular monolith for the Qeet ID identity platform. Single Go service,
single Postgres database with one schema per bounded context. Each context
ships an outbox so it can be peeled off into its own service later without
rewriting business logic.

## Layout

```
cmd/server/             # main.go — wires every module
internal/
  config/               # envconfig
  platform/
    db/                 # pgx pool
    errs/               # error vocabulary
    httpx/              # response, auth, principal, middleware
    logger/             # coloured slog handler for dev
    outbox/             # transactional outbox + log publisher
    password/           # bcrypt
    tokens/             # access (JWT) + refresh (opaque) tokens
  audit/                # audit.events writer
  tenant/               # tenant.tenants
  user/                 # "user".users + password credential
  auth/                 # login / refresh / logout / sessions
  rbac/                 # permissions, roles, assignments, check
  http/                 # chi router that mounts every handler
migrations/             # sql, paired up/down
api/openapi.yaml        # placeholder per-context API spec
```

## Run locally

```bash
# Start Postgres only and run the server on the host
docker compose up -d postgres
cp .env.example .env
make migrate-up           # needs `migrate` CLI (golang-migrate)
make run

# Or full stack inside Docker
docker compose up
```

## Smoke test

```bash
# Health
curl localhost:4001/healthz

# Create tenant (dev-trust header bypass)
curl -X POST localhost:4001/v1/tenants \
  -H 'Content-Type: application/json' \
  -H 'X-Dev-User: 00000000-0000-0000-0000-000000000000' \
  -d '{"slug":"acme","name":"Acme Inc"}'

# Create user under that tenant
curl -X POST localhost:4001/v1/users \
  -H 'Content-Type: application/json' \
  -H 'X-Dev-User: 00000000-0000-0000-0000-000000000000' \
  -d '{"tenant_id":"<tenant-id>","email":"a@acme.test","password":"correct horse battery"}'

# Login
curl -X POST localhost:4001/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"<tenant-id>","email":"a@acme.test","password":"correct horse battery"}'
```

## Extracting a context into its own service later

Every module respects six rules:

1. Its own Postgres schema. No cross-schema JOINs.
2. Its own outbox topic.
3. No imports of another module's `internal/` types — wire through interfaces in `cmd/server/main.go`.
4. Its own OpenAPI spec (added under `api/` per context as the surface grows).
5. Every mutation is wrapped in a transaction that writes business rows, audit row, and outbox row together.
6. No shared mutable state.
