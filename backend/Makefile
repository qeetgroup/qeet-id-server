.PHONY: tidy build run test migrate-up migrate-down migrate-force migrate-down-all \
        db-reset db-wipe lint docker-up docker-down

# Auto-load .env so `make run / test / migrate-up` see the same DB_URL,
# JWT_SECRET, etc. that the Go process expects via envconfig.
ifneq (,$(wildcard .env))
    include .env
    export
endif

GO ?= go
DB_URL ?= postgres://postgres:password@localhost:5001/qeet_identity?sslmode=disable

tidy:
	$(GO) mod tidy

build:
	$(GO) build -o bin/qeet-identity ./cmd/server

run:
	$(GO) run ./cmd/server

test:
	$(GO) test ./...

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

docker-up:
	docker compose up -d

docker-down:
	docker compose down

# Full DB reset (local Postgres or anything reachable via $DB_URL).
# Drops every app schema + the migrate state table, then reapplies all
# migrations from zero. Doesn't drop the database itself, so other apps
# on the same Postgres instance are untouched.
#
# Requirement: `psql` in PATH (comes with the standard Postgres install).
db-reset:
	@echo "Resetting database via $(DB_URL)"
	psql "$(DB_URL)" -v ON_ERROR_STOP=1 -c \
		"DROP SCHEMA IF EXISTS audit, auth, rbac, \"user\", tenant, platform CASCADE; DROP TABLE IF EXISTS public.schema_migrations;"
	$(MAKE) migrate-up
	@echo "Database reset complete — tables empty, schemas remigrated."

# Pure golang-migrate alternative — no psql required. Rolls every applied
# migration back via its .down.sql, then re-applies. Slower than db-reset
# (one statement per migration) and prompts for confirmation on `down -all`.
db-wipe:
	@echo y | migrate -path migrations -database "$(DB_URL)" down -all
	migrate -path migrations -database "$(DB_URL)" up
