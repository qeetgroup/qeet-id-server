.PHONY: help install dev dev-backend dev-frontend dev-admin dev-web dev-docs \
        build build-backend build-frontend \
        test test-backend test-frontend test-api test-api-ci \
        lint typecheck format \
        migrate-up migrate-down migrate-force \
        db-up db-down db-reset db-wipe \
        kill kill-backend kill-frontend kill-admin kill-web kill-docs \
        clean

# ── Defaults ────────────────────────────────────────────────────────────────
GO         ?= go
PNPM       ?= pnpm
DB_URL     ?= postgres://postgres:password@localhost:5001/qeet_identity?sslmode=disable

help:                       ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n"} \
	      /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ── Install ─────────────────────────────────────────────────────────────────
install:                    ## Install all dependencies (backend + frontend)
	cd backend  && $(GO) mod tidy
	cd frontend && $(PNPM) install

# ── Development ─────────────────────────────────────────────────────────────
dev:                        ## Run backend + all 3 frontend apps in parallel
	@$(MAKE) -j2 dev-backend dev-frontend

dev-backend:                ## Run backend API only (:8080)
	cd backend && $(MAKE) run

dev-frontend:               ## Run all 3 frontend apps (admin/web/docs)
	cd frontend && $(PNPM) dev

dev-admin:                  ## Run admin dashboard only (:3002)
	cd frontend && $(PNPM) dev:admin

dev-web:                    ## Run marketing site only (:3001)
	cd frontend && $(PNPM) dev:web

dev-docs:                   ## Run docs site only (:3003)
	cd frontend && $(PNPM) dev:docs

# ── Build ───────────────────────────────────────────────────────────────────
build: build-backend build-frontend  ## Build backend + all frontend apps

build-backend:              ## Build the backend binary
	cd backend && $(MAKE) build

build-frontend:             ## Build all frontend apps
	cd frontend && $(PNPM) build

# ── Test ────────────────────────────────────────────────────────────────────
test: test-backend test-frontend  ## Run all tests

test-backend:               ## Run backend tests
	cd backend && $(MAKE) test

test-frontend:              ## Run frontend tests
	cd frontend && $(PNPM) test

test-api:                   ## Run Postman collection via Newman (needs backend up). Pass FOLDER=Auth to scope.
	cd backend/api/postman && ./run.sh $(if $(FOLDER),--folder "$(FOLDER)") $(if $(BASE),--base "$(BASE)")

test-api-ci:                ## Newman run with JUnit + HTML reports under backend/api/postman/reports
	cd backend/api/postman && ./run.sh --ci --skip-501 $(if $(BASE),--base "$(BASE)")

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

kill-frontend: kill-admin kill-web kill-docs  ## Stop all 3 frontend dev servers

kill-admin:                 ## Stop admin dashboard (:3002)
	$(call kill_port,3002,admin)

kill-web:                   ## Stop marketing site (:3001)
	$(call kill_port,3001,web)

kill-docs:                  ## Stop docs site (:3003)
	$(call kill_port,3003,docs)

# ── Quality ─────────────────────────────────────────────────────────────────
lint:                       ## Lint everything
	cd backend  && $(GO) vet ./...
	cd frontend && $(PNPM) lint

typecheck:                  ## Type-check the frontend
	cd frontend && $(PNPM) typecheck

format:                     ## Format the frontend
	cd frontend && $(PNPM) format

# ── Database & migrations ───────────────────────────────────────────────────
db-up:                      ## Start Postgres via docker compose
	cd backend && docker compose up -d

db-down:                    ## Stop Postgres
	cd backend && docker compose down

db-reset:                   ## Wipe all app data: drop schemas via psql, remigrate from zero
	cd backend && $(MAKE) db-reset

db-wipe:                    ## Same idea, but uses `migrate down -all` instead of psql (no psql needed)
	cd backend && $(MAKE) db-wipe

migrate-up:                 ## Apply all pending migrations
	cd backend && $(MAKE) migrate-up

migrate-down:               ## Roll back one migration
	cd backend && $(MAKE) migrate-down

migrate-force:              ## Force migration version (use V=<n>)
	cd backend && $(MAKE) migrate-force V=$(V)

# ── Housekeeping ────────────────────────────────────────────────────────────
clean:                      ## Remove build artifacts and dependency caches
	cd backend  && rm -rf bin/
	cd frontend && $(PNPM) clean
