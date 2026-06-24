# Data Isolation

## Multi-tenant isolation model

Qeet ID uses a **shared database, shared schema, row-level tenant isolation** model. Every tenant's data lives in the same PostgreSQL tables, isolated by `tenant_id`.

This is implemented at three levels:

### 1. SQL query isolation

Every repository query that accesses tenant-scoped data includes `tenant_id = $1` as a WHERE clause or INSERT value. This is enforced by convention and code review — there is no automatic row-level security (PostgreSQL RLS) enforcing it at the DB level.

```sql
-- Correct: scoped query
SELECT id, email FROM "user".users WHERE tenant_id = $1 AND id = $2;

-- Wrong: unscoped query — never do this
SELECT id, email FROM "user".users WHERE id = $1;
```

**Enforcement:** Code reviews, integration tests (`tests/integration/`), and architecture tests verify tenant scoping. A future improvement would add PostgreSQL RLS as a defense-in-depth layer.

### 2. Request context propagation

The tenant ID is extracted from the authenticated JWT claim (`tid`) in `platform/api/rest/httpx/auth.go` and stored in the request context as part of the `httpx.Principal`:

```go
type Principal struct {
    UserID   string
    TenantID string
    Scopes   []string
    // ...
}
```

All repositories receive the `context.Context` that carries the principal, and extract `tenant_id` from it. Services must not accept a `tenant_id` parameter from the HTTP request body — it always comes from the authenticated token.

### 3. Schema-level namespacing

The six PostgreSQL schemas (`tenant`, `user`, `auth`, `rbac`, `audit`, `platform`) provide namespace isolation between bounded contexts. There are no cross-schema JOINs — cross-context data access goes through Go service interfaces, not SQL.

## Audit log isolation

Each tenant has an independent SHA-256 hash chain in `audit.audit_events`. The chain is per-`tenant_id`:

```
Tenant A: event1 → event2 → event3 → ...
Tenant B: event1 → event2 → ...
```

Tenant A's chain is completely independent of Tenant B's chain. A break in Tenant A's chain (e.g., due to a targeted attack) does not affect Tenant B's chain integrity.

## Secrets vault isolation

Per-tenant AES-256-GCM encryption keys are derived from a master key + tenant ID using HKDF:

```
per_tenant_key = HKDF(master_key, salt=tenant_id, info="qeet-vault-v1", len=32)
```

A compromise of one tenant's vault key does not expose another tenant's secrets, even if both are derived from the same master key. The master key itself is protected by environment variable or AWS KMS.

## Cross-tenant access prevention

Mechanisms that prevent a user in Tenant A from accessing Tenant B's data:

1. **JWT claims:** The `tid` claim in the JWT is set at login time and cannot be changed without re-authenticating to the other tenant (via `POST /v1/auth/switch-tenant` — which verifies membership)
2. **Repository scoping:** All queries include `tenant_id = <from_token>`
3. **No tenant ID in request body:** Tenant ID is always from the token, never a user-supplied parameter
4. **Organization membership check:** `switch-tenant` verifies the user is a member of the target tenant before issuing a new token

## Subscription and data segregation

Tenants on different subscription tiers share the same infrastructure. There is no physical separation between tenants. Isolation is logical (row-level), not physical.

For tenants with strict regulatory requirements (e.g., financial services with data residency requirements), a dedicated deployment with a separate database can be configured. Contact the Qeet team for enterprise isolation options.

## Testing isolation

Integration tests (`tests/integration/`) include explicit cross-tenant isolation tests:
- Verify that User A in Tenant X cannot see User B in Tenant Y
- Verify that switching to a tenant without membership fails
- Verify that audit log queries never return events from a different tenant
