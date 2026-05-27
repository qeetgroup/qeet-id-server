# Database rules — Postgres + golang-migrate

Migrations live in [backend/migrations/](../../backend/migrations/). Applied via `make migrate-up`. Local DB on `:5001` (see [Makefile](../../Makefile)).

## Migrations

- **Never edit a migration that's in `main`.** If you need to change it, write a new one with the next four-digit prefix.
- Every `.up.sql` has a matching `.down.sql` with the same prefix and the same migration name.
- DDL goes inside one `BEGIN; ... COMMIT;` block per migration. Postgres DDL is transactional — use it.
- Prefix is zero-padded to four digits: `0030_add_xyz.up.sql`. Find the next number by `ls backend/migrations/ | sort | tail`.
- Don't reorder columns or drop indexes without an explicit migration that says so. Even "cosmetic" reorders break clients on some drivers.

## Schemas

Domain-grouped, one schema per bounded context:

- `platform` — outbox, scheduler, system tables
- `tenant` — tenants, plans
- `"user"` — users, profiles (quoted in SQL — `user` is reserved)
- `auth` — sessions, refresh tokens, password credentials
- `rbac` — roles, permissions, assignments
- `audit` — audit events (append-only, hash-chained)

When adding a new module, decide which schema it belongs to before writing the migration. New schemas need a strong reason.

## Tenancy

- Every business row carries `tenant_id UUID NOT NULL` with a foreign key to `tenant.tenant(id)`.
- Queries that touch business data filter by `tenant_id`. No exceptions for "admin" queries — the actor's tenant is always known.
- Cross-tenant access returns **403**, not 404. (404 leaks existence.)

## Primary keys

- `id UUID PRIMARY KEY DEFAULT gen_random_uuid()` — UUIDs everywhere, generated server-side. Don't use `bigserial` or accept client-provided IDs.

## Soft-delete

- Only the few tables that need it use `deleted_at TIMESTAMPTZ NULL`. Default queries filter `WHERE deleted_at IS NULL`.
- Don't add `deleted_at` reflexively. Hard delete is fine for most tables — soft delete is a feature with a cost (every query gets a predicate).

## Timestamps

- `created_at TIMESTAMPTZ NOT NULL DEFAULT now()`.
- `updated_at TIMESTAMPTZ NOT NULL DEFAULT now()` only on tables that update in place. Update it in the repo's `UPDATE` statement, not via a trigger.

## Indexes

- Foreign keys are indexed. Postgres doesn't auto-index FKs — add `CREATE INDEX` in the same migration as the FK.
- Tenant-scoped queries: index on `(tenant_id, <whatever>)`, not `(<whatever>, tenant_id)`. Tenant first.

## Audit trail

- Every mutation calls [`audit.Record(ctx, tx, audit.Event{...})`](../../backend/internal/audit/audit.go) inside the same transaction.
- The hash chain seed for a tenant's first row is sixty-four `0` characters. Don't reseed.
- Don't audit reads. (Yet — if/when we add read-audit it goes in a separate table.)

## Outbox (domain events)

- User-visible domain events (user lifecycle, auth events, RBAC changes, API key rotation, webhook config) call [`outbox.Enqueue(ctx, tx, outbox.Event{...})`](../../backend/internal/platform/outbox/outbox.go) inside the same transaction.
- The dispatcher polls after commit and fans out to webhooks. Don't try to publish from the service directly — you'll lose events on rollback.
- Pick a `Topic` and `EventType` consistent with neighbouring modules. Grep before inventing.

## Running things

- `make migrate-up` — apply pending migrations.
- `make migrate-down` — rolls back ONE. **Production: never.** Local: fine for testing the inverse.
- `make migrate-force V=<n>` — force the migrations table to think it's at version `n`. Recovery only — don't use as a normal workflow.
- `make db-reset` / `make db-wipe` — drops every schema and reapplies. **Deny-listed by [.claude/settings.json](../settings.json)** — requires manual confirmation each time.

## Don't

- ❌ Edit a migration that already shipped.
- ❌ Use timestamps as natural keys.
- ❌ Store secrets, raw tokens, or passwords in plaintext columns. Hash with argon2 (passwords) or use the dedicated `auth.*` tables.
- ❌ Add a column without a backfill strategy for existing rows. `NOT NULL` columns need a `DEFAULT` or an `UPDATE` step in the same migration.
