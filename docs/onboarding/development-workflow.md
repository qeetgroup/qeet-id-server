# Development Workflow

## Git workflow

**Primary branch:** `feat/enterprise-phase1-deploy` (current development branch)  
**Target for PRs:** Same branch

```bash
# Create a feature branch from the current dev branch
git checkout -b feat/my-feature

# After your changes are ready
git push origin feat/my-feature
# Open PR → feat/enterprise-phase1-deploy
```

## Before you start any work

```bash
nvm use            # frontend builds require Node ≥24 (from .nvmrc); system default is v18
make install       # ensure deps are current: go mod tidy + pnpm install
```

## Making a backend change

1. Edit files in `domains/`, `platform/`, or `cmd/`
2. Run the server: `make dev-backend` (hot-restart not built-in; kill + restart)
3. Test: `make test` (unit) + `make test-integration` (integration, needs Docker)
4. Lint: `make lint`

## Making a database change

**Never edit an applied migration.** Add a new pair:

```bash
# Create new files
touch platform/database/platform/database/migrations/0063_my_change.up.sql
touch platform/database/platform/database/migrations/0063_my_change.down.sql

# Apply
make migrate-up

# If something went wrong
make migrate-down   # roll back ONE step (dev only)
```


## Making a frontend change

**Admin console (`@qeetid/admin`):**
```bash
make dev-admin    # starts Vite dev server on :3002
```

The admin console uses **TanStack Router with file-based routing**. New route files are auto-detected, but `routeTree.gen.ts` must be regenerated. Do this by starting `vite dev` (which regenerates on startup), then continuing:

```bash
# Regenerate routeTree.gen.ts
pnpm --filter @qeetid/admin exec vite dev
# Wait for "Generated routeTree.gen.ts" in output, then Ctrl+C
make dev-admin    # now start normally
```

**Login app (`@qeetid/login`):**
```bash
make dev-login    # starts Next.js dev on :3004
```

**Website (`@qeetid/web`):**
```bash
make dev-web      # starts Next.js dev on :3001
```

## Adding a new API endpoint

Follow [adding-a-domain.md](adding-a-domain.md) for a full new domain. For adding a route to an existing domain:

1. Add the handler method to `http.go`
2. Register it in `Mount()`
3. Add to `api/openapi/` (CI enforces this)
4. Run `go test ./platform/api/rest/... -run TestOpenAPICoverage` to verify

## Testing

```bash
make test               # Go unit tests + frontend tests (no Docker)
make test-backend       # Go unit tests only
make test-integration   # Go integration tests (needs Docker, ~2 min)
make test-api           # Postman/Newman against live API on :4001
make test-api FOLDER=Auth   # Scope to one Postman folder
make typecheck          # TypeScript type checking across all frontend apps
make lint               # Go lint (golangci-lint) + frontend ESLint
```

Single Go test:
```bash
go test ./domains/access/authentication/... -run TestLogin_Success -v -count=1
```

## Adding an API test to Postman

1. Open `api/postman/qeet-id.postman_collection.json` in Postman
2. Add your request to the appropriate folder
3. Add test assertions (Postman test scripts)
4. Export and overwrite the collection file

## Environment variables

Local environment variables live in `.env` (gitignored). Start from the example:
```bash
cp .env.example .env
# Edit .env to add any required values
```

Never commit `.env` or any file containing secrets. The safety gate (`Config.Validate()`) will refuse to start in production with insecure defaults — don't bypass it with `SERVICE_ENV=dev` in non-dev environments.

## Common make targets

```bash
make help           # full list of targets
make kill           # free stuck dev-server ports (kills :3001, :3002, :3004, :4001)
make format         # gofmt + prettier
make tidy           # go mod tidy
make build          # compile go binary (ldflags-stamped)
make db-up          # start Postgres container
make db-down        # stop Postgres container
make db-psql        # open psql shell in Postgres container
make db-wipe        # drop and recreate all schemas (dev only)
```

## Code conventions

- Follow the triplet pattern (`domain.go`, `repository.go`, `http.go`) for new domains
- Use `httpx.WriteError(w, r, err)` for all error responses (never `http.Error`)
- Use `httpx.WriteJSON(w, r, v)` for all JSON success responses
- Use `slog` for logging with key/value pairs; never `fmt.Println` or string interpolation
- All config from `platform/config` via `envconfig`; never `os.Getenv` scattered in domains
- SQL always parameterized (`$1`, `$2`); never string-concatenated user input
- Every mutation: audit row in same transaction

## Design system

All frontend apps use `@qeetrix/*` components. Before adding a UI component, check if it exists in the design system:

```bash
ls ../../qeetrix/packages/ui/src/components/
```

Do not duplicate components from `@qeetrix/ui` in the frontend apps.
