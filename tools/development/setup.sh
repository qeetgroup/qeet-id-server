#!/usr/bin/env bash
# One-shot dev environment setup for Qeet ID (macOS with Homebrew).
# Safe to re-run — idempotent for already-installed tools.
set -euo pipefail

info() { echo "▶ $*"; }
ok()   { echo "  ✓ $*"; }

info "Go (1.26 or newer; go.mod's toolchain line fetches go1.27.2 automatically)"
if ! go version 2>/dev/null | grep -qE "go1\.(2[6-9]|[3-9][0-9])"; then
  brew install go
fi
ok "$(go version)"

info "Bun (runtime for the Newman/Postman API-contract runner — api/postman/run.sh)"
if ! command -v bun &>/dev/null; then
  brew install bun
fi
ok "$(bun --version)"

info "golang-migrate"
brew install golang-migrate
ok "$(migrate --version)"

info "k6 (load testing)"
brew install k6
ok "$(k6 version)"

info "semgrep (SAST)"
if ! command -v semgrep &>/dev/null; then
  brew install semgrep
fi
ok "$(semgrep --version)"

info "govulncheck (Go vulnerability scanner)"
go install golang.org/x/vuln/cmd/govulncheck@latest
ok "govulncheck installed"

echo ""
echo "Setup complete. Run: make db-up migrate-up && make dev"
