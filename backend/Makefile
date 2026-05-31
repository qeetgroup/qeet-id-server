.PHONY: tidy build run test migrate-up migrate-down migrate-force migrate-down-all \
        db-reset db-wipe db-psql lint docker-up docker-down

# Auto-load .env so `make run / test / migrate-up` see the same DB_URL,
# JWT_SECRET, etc. that the Go process expects via envconfig.
ifneq (,$(wildcard .env))
    include .env
    export
endif

GO ?= go
DB_URL ?= postgres://postgres:password@localhost:5001/qeet_id?sslmode=disable

# Postgres runs only in Docker now (docker compose service "postgres").
# Admin commands exec into that container, so the host needs no psql install.
# `migrate` still runs on the host and reaches the DB via the published port
# in $(DB_URL). Override these if your compose service / DB name differ.
PG_SERVICE ?= postgres
PG_USER    ?= postgres
PG_DB      ?= qeet_id
PG_PORT    ?= 5001
# Non-interactive psql in the container (-T: no TTY, safe inside make/CI).
PSQL_EXEC   = docker compose exec -T $(PG_SERVICE) psql -U $(PG_USER) -d $(PG_DB) -p $(PG_PORT)

tidy:
	$(GO) mod tidy

build:
	$(GO) build -o bin/qeet-id ./cmd/server

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

# Open an interactive psql shell inside the running Postgres container.
# Replaces a host psql / pgAdmin — no client install needed on the host.
db-psql:
	docker compose exec $(PG_SERVICE) psql -U $(PG_USER) -d $(PG_DB) -p $(PG_PORT)

# Full DB reset. Drops every app schema + the migrate state table, then
# reapplies all migrations from zero. Doesn't drop the database itself, so
# anything else in the same Postgres instance is untouched.
#
# psql runs *inside* the Docker container (compose service "$(PG_SERVICE)"),
# so no host psql install is required. Needs the container up (`make db-up`).
db-reset:
	@echo "Resetting database inside container (compose service: $(PG_SERVICE))"
	$(PSQL_EXEC) -v ON_ERROR_STOP=1 -c \
		"DROP SCHEMA IF EXISTS audit, auth, rbac, \"user\", tenant, platform CASCADE; DROP TABLE IF EXISTS public.schema_migrations;"
	$(MAKE) migrate-up
	@echo "Database reset complete — tables empty, schemas remigrated."

# Pure golang-migrate alternative — no psql required. Rolls every applied
# migration back via its .down.sql, then re-applies. Slower than db-reset
# (one statement per migration) and prompts for confirmation on `down -all`.
db-wipe:
	@echo y | migrate -path migrations -database "$(DB_URL)" down -all
	migrate -path migrations -database "$(DB_URL)" up
