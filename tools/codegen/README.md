# tools/codegen

Code generation scripts and configurations for Qeet ID.

## What lives here

| Tool | How to run | Output |
|---|---|---|
| OpenAPI client | `tools/codegen/openapi-gen.sh` | `sdk/js/sdk/src/generated/` |
| Protobuf / gRPC | _planned_ | see [ROADMAP.md](../../ROADMAP.md) |

> Data access is **hand-written SQL via pgx** — there is no sqlc/ORM codegen step (see [ADR-0003](../../docs/adr/0003-postgresql-hand-written-sql.md)).

## OpenAPI

The contract is split into five bounded-context files under `api/openapi/`. The generator merges them into one document (via `tools/openapi-split merge`) and produces TypeScript types for the JS SDK:

```bash
./tools/codegen/openapi-gen.sh
```

Requires `openapi-typescript` (`bun add -g openapi-typescript`).
