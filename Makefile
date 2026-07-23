.PHONY: install dev build test test-integration bench lint migrate-up migrate-down db-up db-down db-reset seed seed-reset kill

ifneq (,$(wildcard .env))
    include .env
    export
endif

# DB_URL comes from .env (included above); this is the fallback when .env is absent.
DB_URL        ?= postgres://postgres:password@localhost:5001/qeet_id?sslmode=disable
MIGRATIONS_DIR = internal/platform/database/migrations
# k6 targets a running server; from the k6 Docker image the host is
# host.docker.internal. Override for a remote/CI target (e.g. http://localhost:4001).
BASE_URL      ?= http://host.docker.internal:4001

install:
	go mod download

dev:
	go run ./cmd/api

build:
	go build -o bin/qeet-id ./cmd/api

test:
	go test ./...

# Integration flows against an ephemeral Postgres via testcontainers (needs Docker).
test-integration:
	go test -tags integration -count=1 ./tests/integration/...

# Load/perf tests via k6 (Docker image — no host install needed). Needs the
# server running against seeded data first: `make db-up seed dev`. discovery is
# a hard SLO gate; authz is informational at default load (single seeded user,
# so it also exercises the per-user rate limiter). Override BASE_URL for a
# non-Docker/remote target.
bench:
	docker run --rm -i grafana/k6 run -e BASE_URL=$(BASE_URL) - < tests/performance/discovery.js
	-docker run --rm -i grafana/k6 run -e BASE_URL=$(BASE_URL) - < tests/performance/authz.js

lint:
	go vet ./...

db-up:
	docker compose up -d

db-down:
	docker compose down

db-reset:
	docker compose down -v
	docker compose up -d

migrate-up:
	migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" up

migrate-down:
	migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" down 1

seed:
	go run ./cmd/seed

seed-reset:
	go run ./cmd/seed -reset

kill:
	@pids=$$(lsof -nP -iTCP:4001 -sTCP:LISTEN -t 2>/dev/null); \
	[ -n "$$pids" ] && kill $$pids && echo "stopped :4001" || echo ":4001 not running"
