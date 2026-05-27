---
name: add-endpoint
description: End-to-end workflow for adding a new HTTP endpoint to the qeet-identity backend — handler, OpenAPI, Postman, test, audit/outbox, and doc updates. Trigger when the user says "add an endpoint", "new route", "new handler", "expose X over HTTP", or anything that introduces a new HTTP surface.
---

# Add a new endpoint — full workflow

Adding an endpoint touches five artefacts. Skipping any of them is a half-done feature in this codebase.

## Phase 0 — Confirm scope

Before writing any code, restate to the user:

1. The verb + path (e.g. `POST /v1/users/{user_id}/recovery-codes`).
2. The owning module (existing one under `backend/internal/`, or do we need a new one).
3. Request shape (fields, validation) and response shape.
4. Whether this is a mutation (needs `audit.Record` + possibly `outbox.Enqueue`) or a read.
5. Whether it needs RBAC. Which permission(s) does it require?

If any of these is unclear, **stop and ask**. Don't guess at the contract.

## Phase 1 — Find the right module

Read [backend/internal/http/router.go](../../../backend/internal/http/router.go) to see where the existing routes for this surface live. The new handler goes in that module's `http.go` (or `<module>.go` for collapsed modules).

If there's no obvious owner, the answer is usually a new module — switch to the [/module-new](../../commands/module-new.md) flow first, then come back here.

Read [../../rules/backend.md](../../rules/backend.md) and [../../rules/api.md](../../rules/api.md) before writing.

## Phase 2 — Implement the handler

Order:

1. **Domain** — add request/response types and a service method signature in the module's `domain.go` (or top of the collapsed file).
2. **Repository** — add the SQL in `repository.go`. Tenancy filter mandatory (see [../../rules/database.md](../../rules/database.md)).
3. **Service** — orchestrate: open tx, call repo, call `audit.Record(ctx, tx, ...)` for mutations, call `outbox.Enqueue(ctx, tx, ...)` if it's a user-visible event, commit.
4. **HTTP** — register the route on the module's chi sub-router, decode the body, call the service, translate domain errors to status codes at the boundary.

No new comments unless the *why* is genuinely non-obvious.

## Phase 3 — OpenAPI

Open [backend/api/openapi.yaml](../../../backend/api/openapi.yaml). Add the path + operation with:

- `operationId` (unique, stable — SDK consumers depend on it).
- `summary` + `tags` matching neighbouring operations.
- Request body schema, referencing `components.schemas` if reusable.
- 2xx and 4xx responses with the project's standard error envelope.

If you're adding a reusable type, define it under `components.schemas` rather than inline.

## Phase 4 — Postman

Open [backend/api/qeet-identity.postman_collection.json](../../../backend/api/qeet-identity.postman_collection.json). Add a request in the matching folder (Auth, Users, Tenants, …). The request must have:

- A name that mirrors the operationId, in human form.
- Headers (`Content-Type`, `Authorization` if needed).
- A `tests` block asserting at minimum: status code, content-type, one body shape check.
- Any environment variable reads (`{{access_token}}`, `{{user_id}}`) populated by earlier requests in the folder.

Validate locally with `make test-api FOLDER="<your folder>"` after starting the backend.

## Phase 5 — Tests

- A Go test in the module: at least one happy-path and one error-path. Use the real DB (see [../../rules/testing.md](../../rules/testing.md)).
- The Postman request from Phase 4 is your contract test.

## Phase 6 — Docs

- Update [documents/IMPLEMENTATION-STATUS.md](../../../documents/IMPLEMENTATION-STATUS.md) — move the relevant requirement to "done" (or update its sub-checklist).
- Update [documents/FEATURE-MATRIX.md](../../../documents/FEATURE-MATRIX.md) if this completes or starts a capability row.
- If the endpoint is security-relevant, update [documents/PROTOCOL-STATUS.md](../../../documents/PROTOCOL-STATUS.md).

## Phase 7 — Sanity pass

Run the [qeetid-reviewer agent](../../agents/qeetid-reviewer.md) against the change before opening the PR. Specifically it'll catch missing audit/outbox calls and missing OpenAPI/Postman entries.

## Done when

All five artefacts updated, tests green (`make test`), API suite passes (`make test-api`), reviewer agent reports no blockers, and the docs reflect the new state.
