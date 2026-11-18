.PHONY: install dev dev-secrets build test test-db lint sqlc sqlc-check openapi openapi-check vuln sast secrets scan-image obs-up obs-down dev-observed ci migrate-down db-up db-down db-reset seed seed-reset kill

# Tool versions; keep in step with .github/workflows/ci.yml.
GOLANGCI_VERSION    = v2.15.0
SQLC_VERSION        = v1.31.1
GOVULNCHECK_VERSION = v1.9.0
GOSEC_VERSION       = v2.30.0
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

# `make dev`, observed: JSON logs, also appended to bin/logs/api.log for Loki, and traces to the local
# collector. Start the stack first with `make obs-up`; Grafana is http://localhost:3300.
dev-observed: dev-secrets
	@mkdir -p bin/logs
	@echo "starting qeet-id on :$${HTTP_PORT:-4001}, observed (logs bin/logs/api.log, traces localhost:4318)"
	@JWT_SIGNING_KEY="$$(cat $(SECRETS_DIR)/jwt_es256.pem)" \
	 SAML_IDP_KEY="$$(cat $(SECRETS_DIR)/saml_idp_key.pem)" \
	 SAML_IDP_CERT="$$(cat $(SECRETS_DIR)/saml_idp_cert.pem)" \
	 LOG_FORMAT=json OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
	 go run ./cmd/api 2>&1 | tee -a bin/logs/api.log

# The local observability stack (docker-compose.yml, profile observability): the OpenTelemetry
# Collector, Prometheus with the alert and SLO rules, Alertmanager (to Mailpit), Loki, Tempo, Grafana,
# and the PostgreSQL and blackbox exporters. obs-down stops only these services.
OBS_SERVICES := otel-collector prometheus alertmanager loki tempo grafana postgres-exporter blackbox-exporter
obs-up:
	@mkdir -p bin/logs
	docker compose --profile observability up -d $(OBS_SERVICES)
	@echo "Grafana http://localhost:3300 · Prometheus http://localhost:9090 · Alertmanager http://localhost:9093 · alert mail http://localhost:8025"
obs-down:
	docker compose --profile observability stop $(OBS_SERVICES)

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

# Regenerate every package's dbgen/ from its queries.sql, as listed in sqlc.yaml.
sqlc: $(SQLC)
	@"$(SQLC)" generate

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

# Secret scan with the same gitleaks as CI, in Docker: the git history, then the working tree as it
# is (uncommitted work too), skipping what .gitleaks.toml lists. Findings are redacted.
GITLEAKS_IMAGE := ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
secrets:
	docker run --rm -v "$(CURDIR):/repo" -w /repo $(GITLEAKS_IMAGE) git --redact --exit-code 1 --config .gitleaks.toml .
	docker run --rm -v "$(CURDIR):/repo" -w /repo $(GITLEAKS_IMAGE) dir --redact --exit-code 1 --config .gitleaks.toml .

# Container scan with Trivy, in Docker: builds the server image, then reports HIGH and CRITICAL
# vulnerabilities that have a fix in its OS packages and binaries, and misconfigurations in the
# Dockerfile and compose files. The image is handed over as a saved tar, not the Docker socket.
TRIVY_IMAGE := aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
TRIVY := docker run --rm -v qeet-id-trivy-cache:/root/.cache/trivy -v "$(CURDIR):/repo" -w /repo $(TRIVY_IMAGE)
scan-image:
	docker build -q -t qeet-id-server:scan . >/dev/null
	@mkdir -p bin && docker save qeet-id-server:scan -o bin/image-scan.tar
	$(TRIVY) image --input bin/image-scan.tar --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed --no-progress
	$(TRIVY) config --exit-code 1 --severity HIGH,CRITICAL .
	@rm -f bin/image-scan.tar

# The full local gate before a push (CI runs only Verify): build, every test
# with the race detector, the database ones too (needs Docker), lint (with
# vet), generated SQL and API documents, and the vulnerability, security and secret scans.
ci:
	go build ./...
	$(MAKE) test-db lint sqlc-check openapi-check vuln sast secrets
	@echo "ci: every check passed"

# Fail if any dbgen/ differs from what sqlc generates, or a queries.sql is not
# listed in sqlc.yaml (its dbgen/ would never be checked).
sqlc-check: $(SQLC)
	@for q in $$(find internal -name queries.sql); do \
		grep -qx "    queries: $$q" sqlc.yaml || { echo "sqlc-check: $$q is not listed in sqlc.yaml"; exit 1; }; \
	done
	@"$(SQLC)" diff

# The five API documents in api/openapi are built from api/openapi/src by
# Redocly CLI, pinned in api/openapi/src/bun.lock. Needs Bun.
OPENAPI_DIR  = api/openapi
OPENAPI_DOCS = auth management federation developer operations
REDOCLY      = REDOCLY_TELEMETRY=off REDOCLY_SUPPRESS_UPDATE_NOTICE=true bun --bun node_modules/.bin/redocly

# openapi_build writes the five API documents into the absolute directory $(1).
openapi_build = cd $(OPENAPI_DIR)/src && bun install --frozen-lockfile --silent && \
	for doc in $(OPENAPI_DOCS); do \
		log="$$($(REDOCLY) bundle "$$doc/openapi.yaml" -o "$(1)/$$doc.body.yaml" 2>&1)" || { echo "$$log"; exit 1; }; \
		{ echo "\# Generated by make openapi from api/openapi/src/$$doc/. Edit the sources, not this file."; \
			cat "$(1)/$$doc.body.yaml"; } > "$(1)/$$doc.yaml" && rm "$(1)/$$doc.body.yaml"; \
	done

# Rebuild the API documents after editing api/openapi/src.
openapi:
	@($(call openapi_build,$(CURDIR)/$(OPENAPI_DIR)))
	@echo "openapi: built $(OPENAPI_DOCS)"

# Lint the API sources with the rules in api/openapi/src/redocly.yaml, then fail
# if a committed API document differs from what its sources build. Builds into
# a temporary directory, so it never touches the working tree.
openapi-check:
	@(cd $(OPENAPI_DIR)/src && bun install --frozen-lockfile --silent && \
		log="$$($(REDOCLY) lint 2>&1)" || { echo "$$log"; exit 1; })
	@out="$$(mktemp -d)" && trap 'rm -rf "$$out"' EXIT && \
	($(call openapi_build,$$out)) && \
	for doc in $(OPENAPI_DOCS); do \
		cmp -s "$$out/$$doc.yaml" "$(OPENAPI_DIR)/$$doc.yaml" || \
			{ echo "$(OPENAPI_DIR)/$$doc.yaml is out of date: run make openapi"; exit 1; }; \
	done && echo "openapi-check: the API documents match their sources"

db-up:
	docker compose up -d

db-down:
	docker compose down

db-reset:
	docker compose down -v
	docker compose up -d

# Rolls one migration back, to try its down file. The server applies migrations
# at start and records the files; one applied by the migrate tool is refused.
migrate-down:
	migrate -path $(MIGRATIONS_DIR) -database "$(DB_URL)" down 1

# Demo data, development only. The seed fills an empty database; seed-reset
# recreates the local database first (as db-reset does), waits for it, then seeds.
seed:
	go run ./cmd/seed

seed-reset: db-reset
	docker compose up -d --wait
	go run ./cmd/seed

kill:
	@pids=$$(lsof -nP -iTCP:4001 -sTCP:LISTEN -t 2>/dev/null); \
	[ -n "$$pids" ] && kill $$pids && echo "stopped :4001" || echo ":4001 not running"
