# platform/api/openapi

OpenAPI spec and validation utilities.

The REST contract lives under [`api/openapi/`](../../../api/openapi/) — five self-contained, bounded-context OpenAPI 3.1 files (no monolithic `openapi.yaml`). The CI coverage test at [`platform/api/rest/openapi_coverage_test.go`](../rest/openapi_coverage_test.go) reads the **union** of all five. Merge them with `go run ./tools/openapi-split merge`.

This package is reserved for OpenAPI-driven code generation helpers and spec-loading utilities.
