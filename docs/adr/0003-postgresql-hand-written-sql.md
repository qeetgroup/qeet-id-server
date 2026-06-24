# ADR-0003: PostgreSQL with Hand-Written SQL over ORM or sqlc

**Status:** Accepted  
**Date:** 2025-Q1  
**Deciders:** Qeet ID core team

---

## Context

Qeet ID requires complex, multi-tenant SQL queries with:
- Mandatory `tenant_id` scoping on every query
- JSONB columns for flexible configuration (branding, auth policy, OIDC client metadata)
- Hash-chain updates in the audit log (requires `RETURNING prev_hash`)
- Cursor-based keyset pagination with per-endpoint sort keys
- PostgreSQL-specific features (advisory locks, LISTEN/NOTIFY candidates, `ON CONFLICT DO UPDATE`)

Three persistence approaches were evaluated:

1. **ORM (GORM, Ent)** — auto-generated queries, struct-based model
2. **sqlc** — type-safe generated code from hand-written SQL
3. **Hand-written SQL over pgx v5** — direct query execution, full SQL control

## Decision

**Hand-written SQL over pgx v5** is the canonical persistence path.

- Each domain's `repository.go` owns its queries as string constants
- `platform/db` provides the connection pool (`*pgxpool.Pool`)
- `platform/pgxerr` maps PostgreSQL constraint errors to domain errors
- `platform/dbutil` provides shared helpers: `UpdateBuilder` (dynamic SET clauses), `DecodeJSONB`

**sqlc:** Evaluated via a one-table pilot, then **removed** — nothing imported it, and the platform's many dynamic, multi-tenant queries (optional filters, conditional `WHERE`, keyset pagination) fit sqlc's static-query model poorly. Hand-written SQL via pgx is the single, project-wide data-access pattern; do not reintroduce a sqlc/hand-written split within a domain.

**ORMs:** Rejected. Multi-tenancy requires explicit `tenant_id` on every query. ORMs make it too easy to accidentally issue unscoped queries, and they hide the SQL needed to write and review safe multi-tenant queries.

## Consequences

**Positive:**
- Every query is explicit, reviewable SQL — no "what does this ORM generate?" debugging
- Multi-tenancy is hard to get wrong: `tenant_id = $1` is always visible
- Full access to PostgreSQL features without ORM abstraction layer
- No reflection-based magic; compile-time type safety via pgx v5 row scanning

**Negative / watch-outs:**
- More boilerplate than an ORM or sqlc for simple CRUD
- Dynamic queries (e.g., filter-by-optional-fields) require careful `UpdateBuilder` patterns to avoid SQL injection
- Row-scanning is hand-written, so adding a column means updating the SQL, the struct, and the scan together

**Security note:** All queries use parameterized placeholders (`$1`, `$2`). String concatenation into SQL is never used. Dynamic query construction (for UPDATE SET clauses) goes through `platform/dbutil.UpdateBuilder` which only appends safe column names, never raw user input.
