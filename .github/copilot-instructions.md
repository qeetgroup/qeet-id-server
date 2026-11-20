# GitHub Copilot — qeet-id-server

**Canonical instructions: [`AGENTS.md`](../AGENTS.md).** Subsystem map and real filenames: [`docs/llm/subsystems.md`](../docs/llm/subsystems.md). This file is a summary; it adds no
architecture.

## Repository

The Go backend of **Qeet ID**, a passkeys-first identity and access platform. Modular monolith,
module `github.com/qeetgroup/qeet-id-server`, chi router, PostgreSQL via pgx + sqlc, port 4001.

**All enforcement lives here.** UIs present; this repository decides.

Context: **L0** `qeet-context` (organization) → **L1** `qeet-id-files` (product) → **L2** this
repository → source.

## Package boundaries — enforced by a test

```text
cmd/*  →  internal/bootstrap  →  internal/<context>  →  internal/platform
```

- `internal/platform/*` must not import a bounded context, `cmd/*`, or `internal/bootstrap`
- bounded contexts must not import `cmd/*` or `internal/bootstrap`
- **all wiring goes in `internal/bootstrap`**

Contexts: `access` · `identity` · `federation` · `developer` · `operations`.

## Security-critical — review carefully

```text
internal/platform/http/httpx/auth.go       organization scope, principal, RequireAuth
internal/platform/http/httpx/csrf.go       CSRF
internal/platform/crypto/tokens/           ES256, kid, rotation
internal/platform/crypto/password/         Argon2id password hashing
internal/platform/config/validate.go       boot-time production gate
internal/bootstrap/router.go               middleware order, route tree
internal/bootstrap/permissions.go          route permissions (each context's in wire_<context>.go)
internal/access/authorization/             RBAC, ABAC, ReBAC, AuthZEN
internal/federation/{saml,scim,ldap}/      untrusted external input
```

## Organization isolation

Take the organization from `httpx.RequireOrganization(r)` — **never** from a path, body or header.
`httpx.EnforceOrganizationScope` checks `{organizationID}` against the caller. Every organization-scoped query carries
`WHERE organization_id = $1`.

**Row-level security is a second layer, not the first.** It covers organization-owned tables in
organization-administration requests only; on a person's own routes, in background jobs, sign-in
and on account-level tables a missing predicate is still a cross-organization data exposure.

## API contracts

`api/openapi/` — five OpenAPI 3.1 documents. **Adding a route without documenting it fails CI**
(`internal/bootstrap/openapi_coverage_test.go`). Update the route and the spec in the same change.

## Migrations

`internal/platform/database/migrations/NNNN_description.{up,down}.sql` — `0001`–`0012` are the schema baseline; read the highest with `ls`.
**Never edit an applied migration.** Additive first.

## Tests

New behaviour ships with a test. Anything touching organization scoping needs a cross-organization denial test.

## Do not

- suggest editing generated `dbgen/` code — change `queries.sql` and regenerate
- suggest wiring outside `internal/bootstrap`
- suggest taking an organization ID from a request parameter
- weaken a security control to make something pass
- invent Make targets — the list in `AGENTS.md` is complete
