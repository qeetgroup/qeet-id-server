.PHONY: install dev dev-secrets build test test-db lint sqlc sqlc-check migrate-up migrate-down db-up db-down db-reset seed seed-reset kill

# Tool versions; keep in step with .github/workflows/ci.yml.
GOLANGCI_VERSION = v2.14.0
SQLC_VERSION     = v1.31.1

ifneq (,$(wildcard .env))
    include .env
    export
endif

# DB_URL comes from .env (included above); this is the fallback when .env is absent.
DB_URL        ?= postgres://postgres:password@localhost:5001/qeet_id?sslmode=disable
MIGRATIONS_DIR = internal/platform/database/migrations
# Persistent local dev signing material (gitignored). Multi-line PEMs can't live in
# the Make-included .env, so `dev` injects these from files (see dev-secrets below).
SECRETS_DIR    = .secrets

install:
	go mod download

# Generate persistent JWT (ES256) + SAML IdP (RSA key + self-signed cert) signing
# material once, into $(SECRETS_DIR) (gitignored). Idempotent: skips whatever is
# already present. The SAML key+cert are always generated as a matching pair.
dev-secrets:
	@mkdir -p $(SECRETS_DIR)
	@[ -s $(SECRETS_DIR)/jwt_es256.pem ] || { \
		openssl ecparam -name prime256v1 -genkey -noout -out $(SECRETS_DIR)/jwt_es256.pem && \
		chmod 600 $(SECRETS_DIR)/jwt_es256.pem && \
		echo "generated $(SECRETS_DIR)/jwt_es256.pem (JWT ES256 signing key)"; }
	@{ [ -s $(SECRETS_DIR)/saml_idp_key.pem ] && [ -s $(SECRETS_DIR)/saml_idp_cert.pem ]; } || { \
		openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
			-keyout $(SECRETS_DIR)/saml_idp_key.pem \
			-out $(SECRETS_DIR)/saml_idp_cert.pem \
			-subj "/CN=Qeet ID SAML IdP" 2>/dev/null && \
		chmod 600 $(SECRETS_DIR)/saml_idp_key.pem $(SECRETS_DIR)/saml_idp_cert.pem && \
		echo "generated $(SECRETS_DIR)/saml_idp_key.pem + saml_idp_cert.pem (SAML IdP pair)"; }

# `make dev` injects the persistent keys from $(SECRETS_DIR) with real newlines —
# a multi-line PEM can't be carried by the Make-included .env. These override the
# blank JWT_SIGNING_KEY, SAML_IDP_KEY and SAML_IDP_CERT exported from .env.
dev: dev-secrets
	@echo "starting qeet-id on :$${HTTP_PORT:-4001} — persistent JWT + SAML keys from $(SECRETS_DIR)/"
	@JWT_SIGNING_KEY="$$(cat $(SECRETS_DIR)/jwt_es256.pem)" \
	 SAML_IDP_KEY="$$(cat $(SECRETS_DIR)/saml_idp_key.pem)" \
	 SAML_IDP_CERT="$$(cat $(SECRETS_DIR)/saml_idp_cert.pem)" \
	 go run ./cmd/api

build:
	go build -o bin/qeet-id ./cmd/api

test:
	go test ./...

# Tenant-isolation and sign-in tests against a real PostgreSQL (needs Docker).
test-db:
	go test -tags integration -count=1 -timeout 10m ./...

# The linters CI runs, over the whole tree including the database tests.
lint:
	go vet ./...
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run --build-tags=integration ./...

# Regenerate every package's dbgen/ from its queries.sql.
sqlc:
	@for cfg in $$(find internal -name sqlc.yaml); do \
		(cd "$$(dirname "$$cfg")" && go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate) || exit 1; \
	done

# Fail if any dbgen/ differs from what sqlc generates.
sqlc-check:
	@for cfg in $$(find internal -name sqlc.yaml); do \
		(cd "$$(dirname "$$cfg")" && go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) diff) || exit 1; \
	done

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
