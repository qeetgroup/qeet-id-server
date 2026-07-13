# test environment

Configuration for running Qeet ID against a **test** database.

## When you need this

- **You usually don't.** Integration tests (`make test-integration`) spin their
  own ephemeral Postgres via **testcontainers** — no static DB required.
- Use this stack when you want a **persistent test DB** on the host, or to point
  `make test-api` (Postman/Newman) at a known instance.

## Usage

```bash
docker compose -f deploy/environments/test/docker-compose.yml up -d
# Postgres on :5002, database qeet_id_test (isolated from dev :5001)

# apply schema + run the API contract suite against it
DB_URL="postgres://postgres:postgres@localhost:5002/qeet_id_test?sslmode=disable" \
  migrate -path platform/database/migrations -database "$DB_URL" up
```

## What runs in CI (the real "test environment")

The authoritative test environment is **CI** ([.github/workflows/ci.yml](../../../.github/workflows/ci.yml)):
a `postgres:16` service container, the full `-race` suite + coverage floor,
golangci-lint, govulncheck, gitleaks, and an OpenAPI lint. This folder is for
local reproduction only.
