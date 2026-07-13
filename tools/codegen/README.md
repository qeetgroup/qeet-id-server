# tools/codegen

Code generation scripts and configurations for Qeet ID.

## What lives here

| Tool | How to run | Output |
|---|---|---|
| Protobuf / gRPC | _planned_ | see [ROADMAP.md](../../ROADMAP.md) |

> Data access is **hand-written SQL via pgx** — there is no sqlc/ORM codegen step (see [ADR-0003](../../docs/adr/0003-postgresql-hand-written-sql.md)).

> SDK type generation moved out with the SDKs — the TypeScript/client SDKs now live in separate `qeet-sdks/` repos, which own their own codegen from the published OpenAPI contract. The five bounded-context specs under `api/openapi/` can still be merged into one document via `tools/openapi-split merge`.
