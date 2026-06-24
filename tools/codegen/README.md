# tools/codegen

Code generation scripts and configurations for Qeet ID.

## What lives here

| Tool | How to run | Output |
|---|---|---|
| sqlc | `make sqlc-generate` | `platform/database/sqlc/` |
| OpenAPI client | `tools/codegen/openapi-gen.sh` | `sdk/js/sdk/src/generated/` |
| Protobuf / gRPC | `tools/codegen/proto-gen.sh` | `platform/api/grpc/` (planned) |

## sqlc

sqlc generates type-safe Go query code from SQL. Config is at `sqlc.yaml`.

```bash
# Regenerate after adding queries to platform/database/sqlc/queries/
make sqlc-generate

# Refresh the schema snapshot after new migrations
make sqlc-schema
```

## OpenAPI

The contract is split into five bounded-context files under `api/openapi/`. The generator merges them into one document (via `tools/openapi-split merge`) and produces TypeScript types for the JS SDK:

```bash
./tools/codegen/openapi-gen.sh
```

Requires `openapi-typescript` (`pnpm add -g openapi-typescript`).
