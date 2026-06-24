.PHONY: help env install tidy dev run dev-backend dev-worker dev-scheduler dev-frontend dev-admin dev-web dev-login dev-example dev-example-react \
        build build-backend build-worker build-scheduler build-migrate build-frontend \
        test test-backend test-frontend test-integration test-api test-api-ci cover cover-html \
        seed seed-reset \
        migrate-up migrate-down migrate-force migrate-down-all \
        db-up db-down db-reset db-wipe db-psql \
        lint lint-go typecheck format \
        kill kill-backend kill-frontend kill-admin kill-web kill-login \
        clean

# ── Defaults ────────────────────────────────────────────────────────────────
GO         ?= go
PNPM       ?= pnpm

# Auto-load .env so make targets see the same env the Go process expects.
ifneq (,$(wildcard .env))
    include .env
    export
endif

# Version metadata stamped into the binary via -ldflags. Overridable in CI
# (e.g. VERSION from a git tag). buildinfo.Get() falls back to embedded VCS info.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILDINFO = github.com/qeetgroup/qeet-id/platform/observability/buildinfo
LDFLAGS ?= -s -w \
	-X $(BUILDINFO).Version=$(VERSION) \
	-X $(BUILDINFO).Commit=$(COMMIT) \
	-X $(BUILDINFO).Date=$(DATE)

# POSTGRES_* come from .env; no password default here. DB_URL is derived from them.
POSTGRES_USER ?= postgres
POSTGRES_DB   ?= qeet_id
POSTGRES_PORT ?= 5001
DB_URL ?= postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@localhost:$(POSTGRES_PORT)/$(POSTGRES_DB)?sslmode=disable

# Schema migrations live under platform/database.
MIGRATIONS_DIR ?= platform/database/migrations

# psql inside the running container
PG_SERVICE ?= postgres
COMPOSE     = docker compose -f deploy/dev/docker-compose.yml
PSQL_EXEC   = $(COMPOSE) exec -T $(PG_SERVICE) psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -p $(POSTGRES_PORT)

help:                       ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n"} \
	      /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

install:                    ## Install all dependencies (Go + JS workspace)
	$(GO) mod tidy
	$(PNPM) install

tidy:                       ## go mod tidy
	$(GO) mod tidy

# ── Development ─────────────────────────────────────────────────────────────
dev:                        ## Run backend + all 3 frontend apps in parallel
	@$(MAKE) -j2 dev-backend dev-frontend

dev-backend:                ## Run backend API only (:4001, from .env)
	$(GO) run ./cmd/server

run: dev-backend            ## Alias for dev-backend (go run ./cmd/server)

dev-worker:                 ## Run worker process (outbox, webhooks, SIEM, audit-integrity)
	$(GO) run ./cmd/worker

dev-scheduler:              ## Run scheduler process (retention, audit-chain-verify, session cleanup)
	$(GO) run ./cmd/scheduler

dev-frontend:               ## Run all 3 frontend apps (admin/web/login)
	$(PNPM) dev

dev-admin:                  ## Run admin console only (:3002)
	$(PNPM) dev:admin

dev-web:                    ## Run marketing site only (:3001)
	$(PNPM) dev:web

dev-login:                  ## Run hosted login only (:3004)
	$(PNPM) dev:login

dev-example:                ## Run the Next.js example app only (:3010, see examples/nextjs-app)
	$(PNPM) --filter @qeetid/example-nextjs dev

dev-example-react:          ## Run the React SPA example only (:3020, see examples/react-app)
	$(PNPM) --filter @qeetid/example-react dev

# ── Build ───────────────────────────────────────────────────────────────────
build: build-backend build-frontend  ## Build backend + all frontend apps

build-backend:              ## Build the backend binary
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/qeet-id ./cmd/server

build-worker:               ## Build the worker binary
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/qeet-id-worker ./cmd/worker

build-scheduler:            ## Build the scheduler binary
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/qeet-id-scheduler ./cmd/scheduler

build-migrate:              ## Build the migration runner binary
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/qeet-id-migrate ./cmd/migrate

build-frontend:             ## Build all frontend apps
	$(PNPM) build

# ── Test ────────────────────────────────────────────────────────────────────
test: test-backend test-frontend  ## Run all tests

test-backend:               ## Run backend tests
	$(GO) test ./...

# Integration tests spin an ephemeral Postgres via testcontainers (needs Docker).
# Gated behind the `integration` build tag so plain `make test` stays Docker-free.
test-integration:
	$(GO) test -tags=integration ./tests/integration/... -timeout 300s

# Unit coverage + regression floor (same gate as CI). Floor is intentionally a
# regression guard, not a target — ratchet COVERAGE_FLOOR up as unit tests grow.
COVERAGE_FLOOR ?= 11.0
cover:                      ## Run unit tests with coverage and enforce the floor
	$(GO) test -count=1 -coverprofile=coverage.out ./...
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {print $$3}' | tr -d '%'); \
	echo "total unit coverage: $${total}% (floor: $(COVERAGE_FLOOR)%)"; \
	awk -v t="$$total" -v f="$(COVERAGE_FLOOR)" 'BEGIN { if (t+0 < f+0) { exit 1 } }' \
	  || { echo "coverage $${total}% is below the $(COVERAGE_FLOOR)% floor"; exit 1; }

cover-html: cover           ## Open the HTML coverage report
	$(GO) tool cover -html=coverage.out

test-frontend:              ## Run frontend tests
	$(PNPM) test

test-api:                   ## Run Postman collection via Newman (needs backend up). Pass FOLDER=Auth to scope.
	cd api/postman && ./run.sh $(if $(FOLDER),--folder "$(FOLDER)") $(if $(BASE),--base "$(BASE)")

test-api-ci:                ## Newman run with JUnit + HTML reports under api/postman/reports
	cd api/postman && ./run.sh --ci --skip-501 $(if $(BASE),--base "$(BASE)")

# ── Database / migrations / codegen (Go) ──────────────────────────────────────
# Populate the DB with a demo workspace for browsing the admin UI.
seed:
	$(GO) run ./cmd/seed

seed-reset:
	$(GO) run ./cmd/seed -reset

# Requires `migrate` CLI from golang-migrate.
migrate-up:
	migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" up

migrate-down:
	migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" down 1

migrate-force:
	migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" force $(V)

# Roll back every applied migration (drops every app table).
migrate-down-all:
	migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" down -all

# Postgres is the only containerised service for local dev; the app runs on the
# host via `make dev-backend`. (The prod stack lives in deploy/prod/.)
db-up:
	$(COMPOSE) up -d

db-down:
	$(COMPOSE) down

# Interactive psql shell inside the Postgres container.
db-psql:
	$(COMPOSE) exec $(PG_SERVICE) psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -p $(POSTGRES_PORT)

# Drop all app schemas (container psql) then remigrate. Needs the container up.
db-reset:
	@echo "Resetting database inside container (compose service: $(PG_SERVICE))"
	$(PSQL_EXEC) -v ON_ERROR_STOP=1 -c \
		"DROP SCHEMA IF EXISTS audit, auth, rbac, \"user\", tenant, platform CASCADE; DROP TABLE IF EXISTS public.schema_migrations;"
	$(MAKE) migrate-up
	@echo "Database reset complete — tables empty, schemas remigrated."

# Same as db-reset but via `migrate down -all` (no psql).
db-wipe:
	@echo y | migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" down -all
	migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" up

# ── Kill stuck dev servers ──────────────────────────────────────────────────
# Each target frees the port if anything is listening on it. Safe to run when
# nothing is bound — it just no-ops.
define kill_port
	@pids="$$(lsof -nP -iTCP:$(1) -sTCP:LISTEN -t 2>/dev/null)"; \
	if [ -n "$$pids" ]; then \
	  echo "killing $(2) on :$(1) (pids: $$pids)"; \
	  kill $$pids 2>/dev/null || true; \
	  sleep 1; \
	  pids="$$(lsof -nP -iTCP:$(1) -sTCP:LISTEN -t 2>/dev/null)"; \
	  if [ -n "$$pids" ]; then echo "  still alive, SIGKILL"; kill -9 $$pids 2>/dev/null || true; fi; \
	else \
	  echo ":$(1) free ($(2))"; \
	fi
endef

kill: kill-backend kill-frontend  ## Stop everything (backend + all 3 frontend apps)

kill-backend:               ## Stop backend (:4001)
	$(call kill_port,4001,backend)

kill-frontend: kill-admin kill-web kill-login  ## Stop all 3 frontend dev servers

kill-admin:                 ## Stop admin console (:3002)
	$(call kill_port,3002,admin)

kill-web:                   ## Stop marketing site (:3001)
	$(call kill_port,3001,web)

kill-login:                 ## Stop hosted login (:3004)
	$(call kill_port,3004,login)

# ── Quality ─────────────────────────────────────────────────────────────────
lint: lint-go               ## Lint everything (Go + frontend)
	$(PNPM) lint

# Go linting. Uses golangci-lint (config: .golangci.yml) when installed —
# same linters as CI — and always runs `go vet`. Install:
#   go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0
lint-go:                    ## Lint Go (golangci-lint if present, else go vet)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed — running 'go vet' only (CI runs the full set)"; \
		$(GO) vet ./...; \
	fi

typecheck:                  ## Type-check the frontend
	$(PNPM) typecheck

format:                     ## Format the frontend
	$(PNPM) format

# ── Housekeeping ────────────────────────────────────────────────────────────
clean:                      ## Remove build artifacts and dependency caches
	rm -rf bin/
	$(PNPM) clean
