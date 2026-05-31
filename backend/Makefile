.PHONY: tidy build run test migrate-up migrate-down migrate-force migrate-down-all \
        db-reset db-wipe db-psql lint docker-up docker-down

# Auto-load .env so make targets see the same env the Go process expects.
ifneq (,$(wildcard .env))
    include .env
    export
endif

GO ?= go

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
