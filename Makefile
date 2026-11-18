# Qeet ID server: every development command.
#
# Each target runs its task in Go (cmd/devtool), so it behaves the same on Windows, macOS and Linux;
# no shell tools are needed, only Go and Docker. Without make, run the same task directly:
#   go run ./cmd/devtool dev
# devtool reads .env itself. Tool versions live in cmd/devtool/checks.go.

DEVTOOL = go run ./cmd/devtool

.PHONY: help install dev-secrets dev dev-observed build kill \
	db-up db-down db-reset seed seed-reset migrate-down \
	test test-db lint fmt fmt-check sqlc sqlc-check openapi openapi-check postman ci \
	vuln sast secrets scan-image \
	load dast fuzz-api sonar-up sonar sonar-down \
	obs-up obs-down

# List the commands with one line each.
help:
	@$(DEVTOOL) help

# ── Set up and run ───────────────────────────────────────────────────────────────────────────────

# Download the Go modules.
install:
	@$(DEVTOOL) install

# Generate the persistent local JWT and SAML signing keys into .secrets/ (once; kept after that).
dev-secrets:
	@$(DEVTOOL) dev-secrets

# Run the API on http://localhost:4001 with the local signing keys (runs dev-secrets first).
dev:
	@$(DEVTOOL) dev

# Run the API as `make dev` does, plus JSON logs to bin/logs/api.log and traces to the local
# collector. Start the observability stack first with `make obs-up`.
dev-observed:
	@$(DEVTOOL) dev-observed

# Build the server binary into bin/qeet-id.
build:
	@$(DEVTOOL) build

# Stop whatever is still listening on :4001.
kill:
	@$(DEVTOOL) kill

# ── Local database and demo data ─────────────────────────────────────────────────────────────────

# Start PostgreSQL :5001, NATS :4222 and Mailpit :8025 (mail UI http://localhost:8025).
db-up:
	@$(DEVTOOL) db-up

# Stop them.
db-down:
	@$(DEVTOOL) db-down

# Recreate them with empty volumes.
db-reset:
	@$(DEVTOOL) db-reset

# Fill an empty local database with demo organizations, people and activity (development only).
seed:
	@$(DEVTOOL) seed

# db-reset, wait for it, then seed.
seed-reset:
	@$(DEVTOOL) seed-reset

# Roll one migration back with the migrate CLI, to try its down file. There is no migrate-up: the
# server applies every pending migration itself when it starts (make dev), and refuses a database
# the migrate CLI moved up, since that keeps no record of the files it applied.
migrate-down:
	@$(DEVTOOL) migrate-down

# ── Tests and checks ─────────────────────────────────────────────────────────────────────────────

# The tests that need no database.
test:
	@$(DEVTOOL) test

# Every test, the database ones too, with the race detector, on one throwaway PostgreSQL (Docker).
test-db:
	@$(DEVTOOL) test-db

# go vet and golangci-lint, as CI runs them.
lint:
	@$(DEVTOOL) lint

# Format every file: Go (gofmt, goimports), JavaScript, JSON, YAML and Markdown (Prettier, settings
# in .prettierrc.json), shell scripts (shfmt).
fmt:
	@$(DEVTOOL) fmt

# Fail if a file isn't formatted, showing what make fmt would change.
fmt-check:
	@$(DEVTOOL) fmt-check

# Regenerate every dbgen/ from its queries.sql (after editing SQL).
sqlc:
	@$(DEVTOOL) sqlc

# Fail if a dbgen/ is stale or a queries.sql isn't listed in sqlc.yaml.
sqlc-check:
	@$(DEVTOOL) sqlc-check

# Rebuild the API documents in api/openapi from api/openapi/src, then the Postman collection in
# api/postman from them (needs Bun).
openapi:
	@$(DEVTOOL) openapi

# Lint the API sources and fail if a built document or the Postman collection is out of date.
openapi-check:
	@$(DEVTOOL) openapi-check

# Rebuild only the Postman collection and its local environment in api/postman, from the API
# documents (make openapi does this too). Import both files into Postman: api/postman/README.md.
postman:
	@$(DEVTOOL) postman

# The full local gate before a push: build, test-db, lint, fmt-check, sqlc-check, openapi-check,
# vuln, sast and secrets.
ci:
	@$(DEVTOOL) ci

# ── Security scans ───────────────────────────────────────────────────────────────────────────────

# Known vulnerabilities in the Go code and its dependencies (govulncheck).
vuln:
	@$(DEVTOOL) vuln

# Static security analysis of the Go code (gosec).
sast:
	@$(DEVTOOL) sast

# Secrets committed in the git history or present in the working tree (gitleaks, Docker).
secrets:
	@$(DEVTOOL) secrets

# Build the server image and scan it and the Dockerfile (Trivy, Docker).
scan-image:
	@$(DEVTOOL) scan-image

# ── Load and security testing (against a running local server; see .env.example's tools list) ──

# Load-test it with k6: sign-in, renewal, reads and discovery, failing when an SLO is missed.
load:
	@$(DEVTOOL) load

# Scan it with OWASP ZAP from the API documents (reports in bin/reports/zap). It sends attacks and
# changes data: use a throwaway server. SCAN_TOKEN reaches the signed-in routes.
dast:
	@$(DEVTOOL) dast

# Fuzz it with Schemathesis from the API documents: no 5xx, every answer as documented (reports in
# bin/reports/schemathesis). It changes data too.
fuzz-api:
	@$(DEVTOOL) fuzz-api

# ── Code analysis ────────────────────────────────────────────────────────────────────────────────

# Start a local SonarQube Community Build on http://localhost:9000 (first sign-in admin / admin).
sonar-up:
	@$(DEVTOOL) sonar-up

# Analyse the code with SonarQube, with the unit tests' coverage. Needs SONAR_TOKEN (a SonarQube token).
sonar:
	@$(DEVTOOL) sonar

# Stop the local SonarQube.
sonar-down:
	@$(DEVTOOL) sonar-down

# ── Observability ────────────────────────────────────────────────────────────────────────────────

# Start the local observability stack: Grafana http://localhost:3300, Prometheus :9090,
# Alertmanager :9093, Loki, Tempo, the OpenTelemetry Collector and the exporters.
obs-up:
	@$(DEVTOOL) obs-up

# Stop it (the database stays up).
obs-down:
	@$(DEVTOOL) obs-down
