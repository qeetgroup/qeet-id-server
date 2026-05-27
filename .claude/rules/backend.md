# Backend rules — `backend/`

Go 1.22, chi router, pgx + pgxpool, PostgreSQL, modular monolith. Entry point: [backend/cmd/server](../../backend/cmd/server). Routes mounted from [backend/internal/http/router.go](../../backend/internal/http/router.go).

## Module shape

- One directory per bounded context under [backend/internal/](../../backend/internal/).
- Standard files for a "full" module: `domain.go`, `repository.go`, `service.go`, `http.go`, plus `*_test.go`. Examples: [internal/user](../../backend/internal/user/), [internal/auth](../../backend/internal/auth/).
- Tiny modules (one type, one or two handlers) collapse everything into `<name>.go`. Example: [internal/invite/invite.go](../../backend/internal/invite/invite.go). Don't split into four files just to match the template.
- Constructors are named `NewRepository`, `NewService`, `NewHandler`. They take only what they need — no global container, no service locator.
- The HTTP sub-router is returned by `NewHandler(...) http.Handler` and mounted from [internal/http/router.go](../../backend/internal/http/router.go).

## Errors

- Domain errors live in `domain.go` as `var ErrXxx = errors.New("...")`. Don't fmt-wrap them at the boundary — use `errors.Is` to compare.
- HTTP handlers translate domain errors to status codes at the edge only. The service layer never knows about HTTP.
- `fmt.Errorf("...: %w", err)` is for adding context; never return a wrapped sentinel that callers need to unwrap differently than the original.

## Validation

- Validate at handler boundaries — that's the system edge. Trust internal callers.
- Don't sprinkle `if x == nil` defensive checks in private functions for things the caller guarantees.

## Transactions

- Mutations run inside a `pgx.Tx`. Open it in the service, pass it to repo methods that need it.
- `audit.Record(ctx, tx, audit.Event{...})` and `outbox.Enqueue(ctx, tx, outbox.Event{...})` go inside the **same** transaction as the business write. See [internal/audit/audit.go](../../backend/internal/audit/audit.go) and [internal/platform/outbox/outbox.go](../../backend/internal/platform/outbox/outbox.go).
- Never start nested transactions. If you need atomicity across multiple repo methods, pass the `tx` down.

## Logging

- Use `log/slog` (stdlib). The pre-configured handler is set up in `cmd/server`.
- Log at boundaries: incoming request (chi middleware does this), outbound external call, mutation outcome.
- Don't log inside hot loops. Don't log secrets, passwords, raw tokens, recovery codes, or session IDs.

## Comments

- Default: none. Only when *why* is non-obvious.
- Don't restate what the function does — the signature does that.
- Don't write "added for X" / "TODO: refactor later" / "used by Y". Git blame, the PR, and grep cover those.
- Package docstrings on `package foo` lines are fine when the package isn't self-evident.

## Dependencies

- No new external dependency for anything stdlib + already-imported libs cover. Audit `go.mod` before adding.
- `chi`, `pgx/v5`, `google/uuid`, `kelseyhightower/envconfig`, `golang-jwt/jwt/v5`, `argon2` — already in. Use these.

## Concurrency

- Background workers (dispatcher, scheduler) live under `internal/platform/`. They take a `context.Context` and shut down on cancellation.
- Don't spawn goroutines from request handlers unless the request explicitly needs fire-and-forget. If you do, attach to a worker queue, don't leak.

## Config

- All config goes through [internal/config/config.go](../../backend/internal/config/config.go) via `envconfig` struct tags. To add a new env var: add a field with `envconfig:"FOO"` and a default if appropriate. Don't read `os.Getenv` from random places.

## Testing

See [testing.md](./testing.md).
