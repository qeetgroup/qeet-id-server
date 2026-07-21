-- Queries for the universal-search domain.
-- Each query fetches one resource type scoped to the caller's tenant.
-- The @q parameter must be passed as '%<query>%' (wildcards included) from
-- the service layer so that the SQL remains a static parameterised query
-- (no dynamic concatenation). Results are merged and scored in-memory by
-- the service before being returned to the caller.
-- pg_trgm is not enabled in this database, so fuzzy matching is ILIKE;
-- prefix/exact scoring is computed in Go after the rows are fetched.

-- name: SearchUsers :many
SELECT id, email, display_name, status, updated_at
FROM "user".users
WHERE tenant_id = @tenant_id
  AND deleted_at IS NULL
  AND (email ILIKE @q OR display_name ILIKE @q)
ORDER BY updated_at DESC, id
LIMIT @row_limit;

-- name: SearchOrganization :many
-- Returns the caller's own tenant when its name or slug matches the query.
-- At most one row (id = tenant_id is a PK equality).
SELECT id, name, slug, status, updated_at
FROM tenant.tenants
WHERE id = @tenant_id
  AND (name ILIKE @q OR slug ILIKE @q)
LIMIT 1;

-- name: SearchGroups :many
SELECT id, name, description, created_at
FROM tenant.groups
WHERE tenant_id = @tenant_id
  AND name ILIKE @q
ORDER BY created_at DESC, id
LIMIT @row_limit;

-- name: SearchRoles :many
SELECT id, name, description, is_system, created_at
FROM rbac.roles
WHERE tenant_id = @tenant_id
  AND name ILIKE @q
ORDER BY created_at DESC, id
LIMIT @row_limit;

-- name: SearchOIDCClients :many
SELECT id, name, client_id, type AS client_type, created_at
FROM auth.oidc_clients
WHERE tenant_id = @tenant_id
  AND (name ILIKE @q OR client_id ILIKE @q)
ORDER BY created_at DESC, id
LIMIT @row_limit;

-- name: SearchAuditEvents :many
SELECT id, action, resource_type, resource_id, created_at
FROM audit.events
WHERE tenant_id = @tenant_id
  AND (action ILIKE @q OR resource_type ILIKE @q)
ORDER BY created_at DESC, id
LIMIT @row_limit;
