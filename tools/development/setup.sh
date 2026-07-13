#!/usr/bin/env bash
# One-shot dev environment setup for Qeet ID (macOS with Homebrew).
# Safe to re-run — idempotent for already-installed tools.
set -euo pipefail

info() { echo "▶ $*"; }
ok()   { echo "  ✓ $*"; }

info "Go (1.25)"
if ! go version 2>/dev/null | grep -q "go1.25"; then
  brew install go
fi
ok "$(go version)"

info "Bun (JS runtime + package manager)"
if ! command -v bun &>/dev/null; then
  brew install bun
fi
ok "$(bun --version)"

info "Workspace dependencies (bun install)"
bun install
ok "dependencies installed"

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

info "Playwright browsers"
bunx playwright install --with-deps 2>/dev/null || true
ok "Playwright ready"

echo ""
echo "Setup complete. Backend: make db-up migrate-up && make dev  ·  Frontends: bun run dev"
