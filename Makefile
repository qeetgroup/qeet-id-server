.PHONY: install dev dev-secrets build test test-db lint sqlc sqlc-check vuln sast ci migrate-up migrate-down db-up db-down db-reset seed seed-reset kill

# Tool versions; keep in step with .github/workflows/ci.yml.
GOLANGCI_VERSION    = v2.14.0
SQLC_VERSION        = v1.31.1
GOVULNCHECK_VERSION = v1.9.0
GOSEC_VERSION       = v2.29.0
GOSEC_XTOOLS        = v0.52.0

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

# Every test, the database ones too, with the race detector (needs Docker).
# One PostgreSQL serves the run: the first test package migrates a template
# database and each gets a copy of it (see internal/platform/database/dbtest).
test-db:
	@name="qeet-id-dbtest-$$$$"; \
	docker run -d --rm --name "$$name" -e POSTGRES_PASSWORD=postgres -p 127.0.0.1::5432 \
		postgres:16-alpine -c max_connections=400 -c fsync=off -c synchronous_commit=off >/dev/null || exit 1; \
	trap 'docker stop "$$name" >/dev/null' EXIT; \
	until [ "$$(docker logs "$$name" 2>&1 | grep -c 'ready to accept connections')" -ge 2 ]; do sleep 0.2; done; \
	port="$$(docker port "$$name" 5432/tcp | head -1 | sed 's/.*://')"; \
	DBTEST_SERVER="postgres://postgres:postgres@127.0.0.1:$$port/postgres?sslmode=disable" \
		go test -race -tags integration -count=1 -timeout 15m ./...

# The linters CI runs, over the whole tree including the database tests.
lint:
	go vet ./...
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run --build-tags=integration ./...

# sqlc, built once and cached in GOPATH/bin: go run per package costs a second
# each, over some sixty packages.
SQLC = $(shell go env GOPATH)/bin/sqlc-$(SQLC_VERSION)

$(SQLC):
	@dir="$$(mktemp -d)" && GOBIN="$$dir" go install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) && mv "$$dir/sqlc" "$@"

# Regenerate every package's dbgen/ from its queries.sql.
sqlc: $(SQLC)
	@for cfg in $$(find internal -name sqlc.yaml); do \
		(cd "$$(dirname "$$cfg")" && "$(SQLC)" generate) || exit 1; \
	done

# Known vulnerabilities in what ships (cmd/ and internal/), as CI gates on.
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./cmd/... ./internal/...

# gosec, built against a current x/tools as CI does (the released binary can't
# read this Go version's export data), cached in GOPATH/bin.
sast:
	@bin="$$(go env GOPATH)/bin/gosec-$(GOSEC_VERSION)"; \
	[ -x "$$bin" ] || { dir="$$(mktemp -d)" && (cd "$$dir" && go mod init gosec-build >/dev/null 2>&1 && \
		go get github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) golang.org/x/tools@$(GOSEC_XTOOLS) && \
		go build -o "$$bin" github.com/securego/gosec/v2/cmd/gosec) || exit 1; }; \
	"$$bin" -quiet -conf .gosec.json -exclude-dir='.*dbgen' -exclude-generated ./...

# Every check CI runs, locally: build, every test with the race detector, the
# database ones too (needs Docker), lint (with vet), generated SQL, and the
# vulnerability and security scans.
ci:
	go build ./...
	$(MAKE) test-db lint sqlc-check vuln sast
	@echo "ci: every check passed"

# Fail if any dbgen/ differs from what sqlc generates.
sqlc-check: $(SQLC)
	@for cfg in $$(find internal -name sqlc.yaml); do \
		(cd "$$(dirname "$$cfg")" && "$(SQLC)" diff) || exit 1; \
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
