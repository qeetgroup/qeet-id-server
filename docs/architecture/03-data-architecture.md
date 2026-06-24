# Data Architecture

## PostgreSQL multi-schema design

Qeet ID uses a **single PostgreSQL instance** with multiple schemas for bounded-context isolation. Schema-per-context ensures that tables from different domains don't bleed into each other and establishes a clean boundary for future service extraction.

| Schema | Owner context | Key tables |
|---|---|---|
| `tenant` | identity/organizations | `tenants`, `tenant_branding`, `tenant_domains` |
| `user` | identity/users | `users`, `groups`, `group_members`, `invitations` |
| `auth` | access, federation | `credentials`, `passkey_credentials`, `webauthn_sessions`, `mfa_secrets`, `sessions`, `oidc_clients`, `saml_connections`, `social_providers`, `api_keys`, `service_principals` |
| `rbac` | access/authorization | `roles`, `permissions`, `user_roles`, `role_permissions`, `relation_tuples` |
| `audit` | operations/audit | `audit_events` (hash-chained), `log_sinks` |
| `platform` | operations, developer | `outbox`, `outbox_dlq`, `notifications`, `billing_plans`, `billing_checkouts`, `agents`, `agent_credentials`, `vc_credentials`, `vc_revocations`, `secrets` |

> **Rule:** No cross-schema JOINs. If context A needs data owned by context B, it resolves it through a Go service call (interface-mediated), never by joining across schemas in SQL.

## Multi-tenancy

Every mutable table carries a `tenant_id` column. All repository queries are scoped to the tenant passed in the request context — there is no "global" view of users or resources.

```sql
-- Example: list users for a specific tenant only
SELECT id, email, display_name FROM "user".users
WHERE tenant_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC;
```

The `tenant_id` is extracted from the authenticated principal in `platform/api/rest/httpx` and flows via `context.Context` through service → repository layers. Repositories **must not** run unscoped queries on tenant-owned tables.

## Migration strategy

Migrations live in [`platform/database/migrations/`](../../platform/database/migrations/) as golang-migrate SQL pairs (`NNNN_name.up.sql` / `NNNN_name.down.sql`).

**Rules:**
- Never edit an applied migration. Add a new pair instead.
- Migrations are sequential (0001–0062 as of pre-1.0).
- Migrations run automatically on app startup: `platform/database/migrations/runner.go` embeds all SQL files with `//go:embed *.sql` and calls `migrate.Up()` before the HTTP server starts. This is a no-op when already up-to-date, and fails fast (preventing startup) if a migration errors.

Apply locally:
```bash
make migrate-up        # apply all pending
make migrate-down      # roll back one step (dev only)
make migrate-down-all  # roll back everything (dev only)
```

## Persistence layer

**Canonical path: hand-written SQL over pgx v5.**

Each domain follows the triplet pattern:
- `domain.go` — exported types and input structs
- `repository.go` — `*pgxpool.Pool`-backed persistence
- `http.go` — HTTP handler and route mounting

Repositories handle their own SQL. The `platform/database/postgres/dbutil` package provides shared helpers (`UpdateBuilder`, JSONB decode). The `platform/database/postgres/pgxerr` package maps PostgreSQL constraint errors to domain errors (`IsUnique`, `IsForeignKey`, etc.).

**sqlc:** Evaluated via a one-table pilot and **removed** — it was unused, and dynamic multi-tenant queries fit it poorly. Hand-written SQL via pgx is the single data-access pattern; don't reintroduce sqlc.

## Transactional pattern

Every mutation that touches more than one table runs inside a single `pgx.Tx`:

```
business row  ┐
audit row      ├── single pgx.Tx (committed or rolled back together)
outbox row    ┘
```

The service layer owns the transaction. Handlers stay thin and never manage transactions directly. This ensures:
1. Mutations are atomic — partial writes never happen.
2. Audit events are never lost (they commit with the business row).
3. Outbox events are never duplicated or dropped relative to the business state.

## Key entity relationships

```
tenants (tenant schema)
  └─► users (user schema) [via tenant_id]
        ├─► user_roles (rbac schema) [M:N via roles]
        ├─► passkey_credentials (auth schema)
        ├─► mfa_secrets (auth schema)
        └─► audit_events (audit schema)

tenants
  ├─► oidc_clients (auth schema) — apps that use Qeet ID as IdP
  ├─► saml_connections (auth schema) — enterprise SSO connections
  ├─► api_keys (auth schema)
  ├─► agents (platform schema) — AI-agent definitions
  ├─► billing_plans (platform schema)
  └─► log_sinks (audit schema) — SIEM streaming config
```

## Soft deletes

Users and several other entities use soft deletes (`deleted_at IS NULL` filter). The `operations/retention` context runs a background worker that permanently purges soft-deleted records after the tenant-configured retention period, satisfying GDPR right-to-erasure obligations.

## JSONB usage

Some columns store structured data as PostgreSQL JSONB (e.g., tenant branding config, auth policy rules, OIDC client metadata). The `platform/database/postgres/dbutil` package provides a shared `DecodeJSONB` helper used across repositories.

## Connection pool

`platform/database/postgres` wraps a `pgxpool.Pool`. Configuration (max connections, idle timeout) comes from environment variables via `platform/config`. The `/readyz` probe issues a `pool.Ping()` to verify database connectivity before reporting healthy.
