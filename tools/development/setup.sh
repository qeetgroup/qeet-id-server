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

info "Node (nvm v22)"
if ! command -v nvm &>/dev/null; then
  brew install nvm
  echo 'export NVM_DIR="$HOME/.nvm" && [ -s "$(brew --prefix)/opt/nvm/nvm.sh" ] && . "$(brew --prefix)/opt/nvm/nvm.sh"' >> ~/.zshrc
  # shellcheck disable=SC1091
  export NVM_DIR="$HOME/.nvm"
  [ -s "$(brew --prefix)/opt/nvm/nvm.sh" ] && . "$(brew --prefix)/opt/nvm/nvm.sh"
fi
nvm install   # reads .nvmrc (Node 24)
nvm use       # reads .nvmrc (Node 24)
ok "$(node --version)"

info "pnpm 9.15.4"
npm install -g pnpm@9.15.4
ok "$(pnpm --version)"

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
nvm use   # reads .nvmrc (Node 24)
pnpm --filter @qeetid/e2e exec playwright install --with-deps 2>/dev/null || true
ok "Playwright ready"

echo ""
echo "Setup complete. Run: make install && make db-up migrate-up && make dev"
