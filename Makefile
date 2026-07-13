.PHONY: install dev build test lint migrate-up migrate-down db-up db-down db-reset seed seed-reset kill

ifneq (,$(wildcard .env))
    include .env
    export
endif

# DB_URL comes from .env (included above); this is the fallback when .env is absent.
DB_URL        ?= postgres://postgres:password@localhost:5001/qeet_id?sslmode=disable
MIGRATIONS_DIR = platform/database/migrations

install:
	go mod download

dev:
	go run ./cmd/server

build:
	go build -o bin/qeet-id ./cmd/server

test:
	go test ./...

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
