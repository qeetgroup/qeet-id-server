---
description: Scaffold a new backend domain module under internal/<name>/ with the standard file layout.
---

Create a new backend module. `$ARGUMENTS` is the module name in lowercase (e.g. `notification`). If empty, ask.

Read [../rules/backend.md](../rules/backend.md), [../rules/database.md](../rules/database.md), and [../rules/api.md](../rules/api.md) first — they specify the module shape, audit/outbox wiring, and OpenAPI/Postman obligations you'll need to satisfy.

Steps:

1. Read [backend/internal/http/router.go](../../backend/internal/http/router.go) and one existing small module (e.g. `internal/invite/` or `internal/branding/`) to confirm the current file-layout convention. Match it exactly — don't invent a new shape.
2. Create `backend/internal/<name>/` containing:
   - `domain.go` — types, errors, interfaces.
   - `repository.go` — pgx-backed repo with a constructor `NewRepository(pool *pgxpool.Pool)`.
   - `service.go` — business logic; constructor takes the repo + any deps from `internal/platform`.
   - `http.go` — chi sub-router; constructor `NewHandler(svc *Service)` returning `http.Handler`.
   - `<name>_test.go` — at least one happy-path test.
   - If the module is genuinely tiny (one type, one handler), collapse everything into `<name>.go` instead — match what comparable small modules already do.
3. Mount the new sub-router in `internal/http/router.go` under the appropriate prefix. Keep the mount order alphabetical within its section.
4. If the module owns persistent state, also scaffold a migration via the same flow as `/migration-new`.
5. Update [documents/IMPLEMENTATION-STATUS.md](../../documents/IMPLEMENTATION-STATUS.md) and [documents/FEATURE-MATRIX.md](../../documents/FEATURE-MATRIX.md) — add a row for the new module marked in-progress.
6. Do not add comments restating what the code does. Follow the no-comment-by-default rule from [CLAUDE.md](../../CLAUDE.md).

Report back with: list of files created, the route prefix used, and any TODO markers left in the scaffold so the user can finish them.
