# Codebase Tour

A guided walk through the Qeet ID codebase for new contributors.

## Repository root layout

```
cmd/           Go entrypoints
domains/       Business logic (5 bounded contexts)
platform/      Shared infrastructure
apps/          3 React frontend apps
packages/      Shared JS config (tsconfig)
api/           OpenAPI specs (5 domain files) + Postman collection
tests/         Go integration + architecture tests
docs/          You are here
```

## How to navigate a domain

Every domain follows the **triplet pattern**:

```
domains/access/authentication/
  ├── auth.go         ← types, interfaces, input structs (the domain model)
  ├── repository.go   ← SQL persistence over *pgxpool.Pool
  └── http.go         ← HTTP handler, Mount(), route definitions
```

Large protocol handlers may split into multiple files:
```
domains/federation/oidc/
  ├── oidc.go         ← OIDC types + core service
  ├── core.go         ← authorization code flow
  ├── device.go       ← device flow
  └── http.go         ← handler + Mount()
```

Start at `domain.go` (or the domain-named file) to understand types and interfaces, then `repository.go` for persistence, then `http.go` for the API surface.

## How to find a route

All routes are wired in `platform/api/rest/router.go`. Each domain handler exposes a `Mount(r chi.Router)` method:

```go
// platform/api/rest/router.go
func New(deps Deps) http.Handler {
    r := chi.NewRouter()
    // ...middleware...
    r.Route("/v1", func(r chi.Router) {
        deps.Auth.Mount(r)       // /v1/auth/*
        deps.Users.Mount(r)      // /v1/users/*
        deps.OIDC.Mount(r)       // /v1/oidc/*
        // ...etc
    })
}
```

To find which handler serves a route: search `router.go` for the path prefix, then look at that handler's `http.go`.

## How to find a migration

```bash
ls platform/database/migrations/ | grep <keyword>
# e.g.:
ls platform/database/migrations/ | grep agent
# → 0061_agents.up.sql, 0061_agents.down.sql
```

Migrations are named `NNNN_<name>.{up,down}.sql`. Read the `.up.sql` for the schema definition.

## Platform packages (shared infrastructure)

`platform/` contains cross-cutting infrastructure. Key packages:

| Package | What it does |
|---|---|
| `platform/config` | All env-based configuration; `Config.Validate()` is the prod safety gate |
| `platform/database/postgres` | pgx v5 connection pool |
| `platform/security/tokens` | JWT sign/verify; JWKS; key rotation |
| `platform/api/rest/httpx` | `RequireAuth`, `Principal`, CSRF middleware, security headers |
| `platform/api/rest` | chi v5 router composition root; mounts all handlers |
| `platform/api/rest/errs` | Error vocabulary (`ErrNotFound`, `ErrForbidden`, etc.) |
| `platform/observability/logging` | Structured `slog` with PII redaction |
| `platform/cache/ratelimit` | Token-bucket rate limiter |
| `platform/events/outbox` | Transactional outbox dispatcher + DLQ |
| `platform/messaging/notifier` | Email and SMS dispatch (SMTP, Twilio) |
| `platform/workers` | Background worker supervisor |
| `platform/api/rest/paging` | Keyset cursor pagination |
| `platform/security/hibp` | Have I Been Pwned k-anonymity breach check |

## Dependency injection

`cmd/server/main.go:buildDeps()` is the composition root. It constructs every repository and service, wires them together through interfaces, and assembles the `Deps` struct that the router receives. To trace how a service gets its dependencies:

1. Find the service type in `domains/<context>/<name>/domain.go`
2. Search `buildDeps()` for `<name>.New(...)` to see what it's wired with
3. Follow the interface types to understand cross-domain dependencies

## Reading the OpenAPI spec

`api/openapi/` holds the authoritative API reference as **five bounded-context specs** (`auth`, `management`, `federation`, `developer`, `operations`). To view the whole surface in one place, merge them first:
- **Merge to one file:** `go run ./tools/openapi-split merge > /tmp/openapi.yaml`
- **VS Code:** open any of the five files with the OpenAPI Preview extension
- **Swagger UI:** `docker run -p 8080:8080 -e SWAGGER_JSON=/api.yaml -v /tmp/openapi.yaml:/api.yaml swaggerapi/swagger-ui` (after merging)
- **Stoplight Studio:** Desktop app that renders the merged spec with navigation

## Running a single test

```bash
# Single Go test
go test ./domains/access/authentication/... -run TestLogin_Success -v

# All tests in a context
go test ./domains/access/...

# With race detector
go test -race ./domains/...

# Integration tests (needs Docker)
go test -tags integration ./tests/integration/... -v
```

## Architecture tests

`tests/architecture/arch_test.go` enforces:
- R1: `platform/*` doesn't import `domains/*`
- R2: `domains/*` doesn't import `cmd/*` or `platform/api/rest`

These run as part of `make test`. If you add an import that violates a rule, this test fails.
