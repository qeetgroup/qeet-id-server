.PHONY: help env install dev dev-backend dev-frontend dev-admin dev-web dev-login \
        build build-backend build-frontend \
        test test-backend test-frontend test-api test-api-ci \
        lint typecheck format \
        kill kill-backend kill-frontend kill-admin kill-web kill-login \
        clean

# ── Defaults ────────────────────────────────────────────────────────────────
GO         ?= go
PNPM       ?= pnpm
# DB / migrate / seed targets live ONLY in backend/Makefile (single source of truth).
# Run them from backend/, or without cd: `make -C backend db-up` (etc.).

help:                       ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n"} \
	      /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

install:                    ## Install all dependencies (backend + frontend)
	cd backend  && $(GO) mod tidy
	cd frontend && $(PNPM) install

# ── Development ─────────────────────────────────────────────────────────────
dev:                        ## Run backend + all 3 frontend apps in parallel
	@$(MAKE) -j2 dev-backend dev-frontend

dev-backend:                ## Run backend API only (:4001, from backend/.env)
	cd backend && $(MAKE) run

dev-frontend:               ## Run all 3 frontend apps (admin/web/login)
	cd frontend && $(PNPM) dev

dev-admin:                  ## Run admin dashboard only (:3002)
	cd frontend && $(PNPM) dev:admin

dev-web:                    ## Run marketing site only (:3001)
	cd frontend && $(PNPM) dev:web

dev-login:                  ## Run hosted login only (:3004)
	cd frontend && $(PNPM) dev:login

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

kill-frontend: kill-admin kill-web kill-login  ## Stop all 3 frontend dev servers

kill-admin:                 ## Stop admin dashboard (:3002)
	$(call kill_port,3002,admin)

kill-web:                   ## Stop marketing site (:3001)
	$(call kill_port,3001,web)

kill-login:                 ## Stop hosted login (:3004)
	$(call kill_port,3004,login)

# ── Quality ─────────────────────────────────────────────────────────────────
lint:                       ## Lint everything
	cd backend  && $(GO) vet ./...
	cd frontend && $(PNPM) lint

typecheck:                  ## Type-check the frontend
	cd frontend && $(PNPM) typecheck

format:                     ## Format the frontend
	cd frontend && $(PNPM) format

# ── Housekeeping ────────────────────────────────────────────────────────────
clean:                      ## Remove build artifacts and dependency caches
	cd backend  && rm -rf bin/
	cd frontend && $(PNPM) clean
