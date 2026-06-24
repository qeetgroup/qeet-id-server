# ADR-0015: Six PostgreSQL Schemas for Bounded-Context Isolation

**Status:** Accepted  
**Date:** 2025-Q1 (established in migration 0001)  
**Deciders:** Qeet ID core team

---

## Context

A multi-tenant SaaS identity platform that eventually supports thousands of tenants needs clear data isolation. Options considered:

1. **Single schema, single database** — all tables in the default `public` schema. Simple but all contexts share a namespace; accidental cross-context joins are easy to write.
2. **Database-per-tenant** — maximum isolation but operationally expensive (connection pool explosion, migration complexity).
3. **Schema-per-tenant** — PostgreSQL row-security-level isolation; complex to manage at scale.
4. **Schema-per-bounded-context** — one schema per domain context; `tenant_id` column for multi-tenancy within each schema.

## Decision

Use **six PostgreSQL schemas**, one per bounded context plus a shared platform schema:

| Schema | Owned by | Created in |
|---|---|---|
| `tenant` | identity/organizations | `0001_schemas`, `0003_tenant` |
| `user` | identity/users | `0001_schemas`, `0004_user` |
| `auth` | access + federation | `0001_schemas`, `0005_auth` |
| `rbac` | access/authorization | `0001_schemas`, `0006_rbac` |
| `audit` | operations/audit | `0001_schemas`, `0007_audit` |
| `platform` | operations + developer | `0001_schemas`, `0002_platform_outbox` |

All mutable tables carry a `tenant_id` column. Queries are always scoped by `tenant_id = $1`.

**No cross-schema JOINs.** If a service needs data from another schema, it calls the owning service (interface-mediated) rather than joining across schema boundaries in SQL.

## Consequences

**Positive:**
- Schema-level namespacing: `SELECT * FROM auth.credentials` is unambiguous; no table name collision between contexts
- Accidental cross-context JOINs are caught at query review: `JOIN auth.credentials ON tenant.users.id = auth.credentials.user_id` is immediately visible as a cross-schema query
- Each schema's tables can be granted different PostgreSQL permissions to different roles (future: read replicas with per-schema grants)
- Clean extraction boundary: when a context is extracted to its own service, its schema already has a physical boundary in PostgreSQL

**Negative / watch-outs:**
- `search_path` must be set correctly for each session or queries must use fully-qualified names (`schema.table`). Qeet ID always uses fully-qualified names in SQL
- Foreign keys across schemas are possible in PostgreSQL but we intentionally avoid them — a `user.users.id` referenced from `auth.credentials.user_id` is enforced at the application level (interface-mediated) rather than as a DB-level constraint. This is the trade-off for future extractability
- Six schemas require the migration runner to connect to the right database with permissions to create schemas (handled by `Dockerfile.migrate` running as the owner role)
