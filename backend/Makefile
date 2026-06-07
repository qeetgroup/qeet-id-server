.PHONY: tidy build run test test-integration seed seed-reset sqlc-generate sqlc-schema migrate-up migrate-down migrate-force migrate-down-all \
        db-up db-down db-reset db-wipe db-psql lint

# Auto-load .env so make targets see the same env the Go process expects.
ifneq (,$(wildcard .env))
    include .env
    export
endif

GO ?= go

# Version metadata stamped into the binary via -ldflags. Overridable in CI
# (e.g. VERSION from a git tag). buildinfo.Get() falls back to embedded VCS info.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILDINFO = github.com/qeetgroup/qeet-id/internal/platform/buildinfo
LDFLAGS ?= -s -w \
	-X $(BUILDINFO).Version=$(VERSION) \
	-X $(BUILDINFO).Commit=$(COMMIT) \
	-X $(BUILDINFO).Date=$(DATE)

# POSTGRES_* come from .env; no password default here. DB_URL is derived from them.
POSTGRES_USER ?= postgres
POSTGRES_DB   ?= qeet_id
POSTGRES_PORT ?= 5001
DB_URL ?= postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@localhost:$(POSTGRES_PORT)/$(POSTGRES_DB)?sslmode=disable

# psql inside the running container
PG_SERVICE ?= postgres
PSQL_EXEC   = docker compose exec -T $(PG_SERVICE) psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -p $(POSTGRES_PORT)

tidy:
	$(GO) mod tidy

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/qeet-id ./cmd/server

run:
	$(GO) run ./cmd/server

# Populate the DB with a demo workspace for browsing the admin UI.
# seed-reset wipes existing data first (dev only). All users share the same
# password printed at the end.
seed:
	$(GO) run ./cmd/seed

seed-reset:
	$(GO) run ./cmd/seed -reset

test:
	$(GO) test ./...

# Integration tests spin an ephemeral Postgres via testcontainers (needs Docker).
# Gated behind the `integration` build tag so plain `make test` stays Docker-free.
test-integration:
	$(GO) test -tags=integration ./test/integration/... -timeout 300s

# sqlc-schema refreshes the schema snapshot sqlc reads (run after new migrations).
sqlc-schema:
	docker compose exec -T $(PG_SERVICE) pg_dump -U $(POSTGRES_USER) -d $(POSTGRES_DB) --schema-only --no-owner --no-privileges > sqlc/schema.sql

# sqlc-generate regenerates the type-safe query package from sqlc/queries.
sqlc-generate:
	sqlc generate

# Requires `migrate` CLI from golang-migrate.
migrate-up:
	migrate -path migrations -database "$(DB_URL)" up

migrate-down:
	migrate -path migrations -database "$(DB_URL)" down 1

migrate-force:
	migrate -path migrations -database "$(DB_URL)" force $(V)

# Roll back every applied migration (drops every app table).
migrate-down-all:
	migrate -path migrations -database "$(DB_URL)" down -all

# Postgres is the only containerised service for local dev; the app runs on the
# host via `make run`. (The prod-shaped stack lives in ../deploy/compose.)
db-up:
	docker compose up -d

db-down:
	docker compose down

# Interactive psql shell inside the Postgres container.
db-psql:
	docker compose exec $(PG_SERVICE) psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -p $(POSTGRES_PORT)

# Drop all app schemas (container psql) then remigrate. Needs the container up.
db-reset:
	@echo "Resetting database inside container (compose service: $(PG_SERVICE))"
	$(PSQL_EXEC) -v ON_ERROR_STOP=1 -c \
		"DROP SCHEMA IF EXISTS audit, auth, rbac, \"user\", tenant, platform CASCADE; DROP TABLE IF EXISTS public.schema_migrations;"
	$(MAKE) migrate-up
	@echo "Database reset complete — tables empty, schemas remigrated."

# Same as db-reset but via `migrate down -all` (no psql).
db-wipe:
	@echo y | migrate -path migrations -database "$(DB_URL)" down -all
	migrate -path migrations -database "$(DB_URL)" up
