# API surface rules

The HTTP surface is the contract. Three artefacts must stay in sync — drift between them is a bug.

| Artefact | Path | Source of truth for |
|---|---|---|
| Go handlers | [backend/internal/](../../backend/internal/) + [internal/http/router.go](../../backend/internal/http/router.go) | Actual behaviour. |
| OpenAPI spec | [backend/api/openapi.yaml](../../backend/api/openapi.yaml) | Documented shape. SDK generation. |
| Postman collection | [backend/api/qeet-identity.postman_collection.json](../../backend/api/qeet-identity.postman_collection.json) | Executable contract tests via Newman. |

## When you add or change a handler

Update **all three** in the same PR:

1. The handler itself (`internal/<module>/http.go`) and its mount in `internal/http/router.go`.
2. The OpenAPI path / schema in `backend/api/openapi.yaml`.
3. The Postman request in the collection, with at least one assertion (status code + one body field).

A behaviour change without a Postman update is incomplete.

## Verbs and paths

- Verbs map to intent: `GET` read, `POST` create, `PATCH` partial update, `PUT` full replace, `DELETE` remove.
- Paths are plural for collections (`/users`, `/tenants`) and use UUIDs for single-resource paths (`/users/{user_id}`). Don't use email or username as a path segment.
- Tenancy is implicit from the actor's token. The path doesn't carry `{tenant_id}` for the actor's own tenant. (Cross-tenant admin paths under `/platform/...` are the exception.)
- Names in paths are snake_case; field names in JSON bodies are snake_case. Stay consistent.

## Responses

- Success: 200 (read), 201 (create), 204 (no content) where appropriate.
- 4xx body uses the project's error envelope. Don't invent new error shapes per module — check what neighbours return first.
- Errors don't leak internals. No SQL strings, no stack traces, no env values in the body.
- Cross-tenant or missing resource → **403** (see [security.md](./security.md)). Never 404 for "not yours".

## Pagination

- List endpoints use cursor-based pagination (`?cursor=...&limit=...`). Don't add offset/page params.
- Default `limit` is sensible (25–50). Max enforced server-side.

## Idempotency

- `POST` endpoints that can be retried (payment, webhook delivery, anything with side effects beyond the DB) accept an `Idempotency-Key` header. Look at existing handlers before inventing your own approach.

## OpenAPI hygiene

- Every operation has `operationId`, `summary`, `tags`, request body schema (if applicable), and at least the 2xx + 4xx responses.
- Schemas live under `components.schemas`. Inline schemas are fine for one-off request bodies; reusable types must be named components.
- Don't break existing `operationId` values — SDK consumers depend on them.

## Postman hygiene

- Folders mirror modules (Auth, Users, Tenants, …). Don't dump new requests at the root.
- Tests block on each request asserts at minimum: status code, content-type, and one body shape check.
- Environment variables for tokens / IDs are set by earlier requests in the same folder. Don't paste live tokens.

## Running the suite

- Local: `make test-api` (backend must be up on `:4000`). Filter: `make test-api FOLDER="Auth"`.
- CI: `make test-api-ci` — JUnit + HTML reports under `backend/api/postman/reports/`.
- Or use the [/api-test](../commands/api-test.md) slash command.

## Don't

- ❌ Add a new handler without the OpenAPI + Postman entries.
- ❌ Rename a field on a stable endpoint. Add the new one, deprecate the old via OpenAPI for at least one release.
- ❌ Use `application/x-www-form-urlencoded` for new endpoints. JSON in, JSON out, except where the spec requires otherwise (OIDC token endpoint, etc.).
