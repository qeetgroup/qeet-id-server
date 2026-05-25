.PHONY: tidy build run test migrate-up migrate-down lint docker-up docker-down

GO ?= go
DB_URL ?= postgres://qeet:qeet@localhost:5432/qeet_identity?sslmode=disable

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

docker-up:
	docker compose up -d

docker-down:
	docker compose down
