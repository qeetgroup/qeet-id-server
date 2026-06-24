# tests/security/

Security-focused tests for Qeet ID. These complement the integration tests by targeting specific security controls.

## Structure

| Directory / File | What it covers |
|---|---|
| `semgrep/` | SAST rules — detect unsafe patterns in Go source (SQL injection, path traversal, weak crypto) |
| `zap/` | OWASP ZAP scan configs — active scan against staging/local |
| `csrf_test.go` | Go tests verifying CSRF protection across all form endpoints |
| `headers_test.go` | Go tests verifying security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, CSP) |
| `auth_bypass_test.go` | Go tests verifying that protected endpoints reject unauthenticated requests |
| `injection_test.go` | Go tests verifying SQL injection resistance via payload fuzzing |

## Run static analysis (semgrep)

```bash
# Install semgrep
brew install semgrep      # macOS
pip install semgrep       # or via pip

# Run Qeet ID rules
semgrep --config tests/security/semgrep/ ./domains/ ./platform/ ./cmd/

# Run OWASP ruleset
semgrep --config p/owasp-top-ten ./domains/ ./platform/
```

## Run Go security tests

```bash
# All security tests (requires running backend)
make db-up migrate-up && make dev-backend &
go test ./tests/security/... -v -timeout 60s
```

## Run OWASP ZAP (requires staging URL)

```bash
# Passive scan
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t https://staging.id.qeet.in \
  -c tests/security/zap/baseline.conf

# Active scan (destructive — staging only, never prod)
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
  -t https://staging.id.qeet.in \
  -c tests/security/zap/active-scan.conf
```

## Dependency vulnerability scan

```bash
# Go
govulncheck ./...

# Node
pnpm audit --audit-level=high
```
