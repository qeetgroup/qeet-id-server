# tools/development

Development environment setup, editor configs, and local tooling.

## Quick setup (macOS)

```bash
./tools/development/setup.sh
```

Installs: Go 1.25, Bun 1.3.14, golang-migrate, k6, semgrep,
govulncheck, Playwright browsers.

## Contents

| File | Purpose |
|---|---|
| `setup.sh` | One-shot dev environment bootstrap |
| `vscode.json` | VS Code workspace settings (copy to `.vscode/settings.json`) |
| `vscode-extensions.json` | Recommended VS Code extensions list |
| `.golangci.yml` | golangci-lint configuration |

## VS Code setup

```bash
cp tools/development/vscode.json .vscode/settings.json
```

## golangci-lint

```bash
# Install
brew install golangci-lint

# Run (uses tools/development/.golangci.yml)
golangci-lint run --config tools/development/.golangci.yml ./...
```
