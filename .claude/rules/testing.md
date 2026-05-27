# Testing rules

## What needs a test

- **Behaviour changes** — yes. The PR has a regression test that fails on `main` and passes on the branch.
- **Pure refactors** (rename, move, inline, extract) — no new test. Existing tests still pass.
- **Bug fixes** — yes, a test that fails without the fix. (If the bug can't be reproduced in a test, say so in the PR.)
- **New backend module** — at least one happy-path service test and one HTTP-layer test.
- **New frontend route** — at minimum, a render-without-crash test. Interactive UI changes need a unit test for the logic + a Postman test for the backend it calls.

## Backend tests — Go

- Run via `make test` (which calls `go test ./...`).
- Use stdlib `testing` + `github.com/stretchr/testify` if it's already imported in the package. Don't add ginkgo / etc.
- Repository tests hit a **real** Postgres — use the test container helper if one exists, otherwise the same DB on `:5001`. Mocking pgx defeats the point.
- Service tests can use a fake repo if the test is about service logic, not SQL.
- HTTP tests use `httptest.NewServer` + chi-mounted handler. Don't import a real network port.
- Time-sensitive tests inject a clock — don't `time.Sleep`. Look for a `Clock` interface in the package; use it.

## Frontend tests

- Run via `make test` (Turbo fans out to each app).
- Use the framework already configured per app — don't add a new test runner.
- Component tests live next to the component: `Button.tsx` + `Button.test.tsx`.
- Don't test what TypeScript already proves (prop types). Test behaviour.

## Contract tests — Postman / Newman

- Every new or changed handler has a Postman request with assertions. See [api.md](./api.md).
- Run: `make test-api` or `/api-test`. CI run: `make test-api-ci`.

## Coverage

- Don't chase a coverage number. A 100%-covered module with no edge-case tests is worse than an 80%-covered one with the right ones.
- Tests run in CI on every PR. Don't merge red.

## Don't

- ❌ Disable a failing test to make CI green. Either fix the code or fix the test. If neither is possible right now, mark the test `t.Skip` with a comment explaining what unblocks it — and open an issue.
- ❌ Use `t.Sleep` to wait for async work. Poll with a deadline or inject a synchronization point.
- ❌ Test private methods directly. If they need testing, the public API is wrong.
- ❌ Commit a test that uses a real external service (Stripe, real IdP). Mock at the HTTP boundary.

## Useful commands

```bash
make test                 # full suite
make test-backend         # Go only
make test-frontend        # JS/TS only
make test-api             # Postman via Newman (backend must be running)
make test-api FOLDER=Auth # scope to one folder
go test ./internal/user/  # one Go package
go test -run TestX ./...  # one test by name
```
