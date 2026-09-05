-- Queries for the auth-hooks domain.
-- All queries are static; no dynamic SQL in this domain.

-- name: ListHooks :many
SELECT id, trigger, url, enabled, fail_open, created_at
FROM tenant.auth_hooks WHERE tenant_id = $1 ORDER BY created_at DESC;

-- name: UpdateHook :execrows
UPDATE tenant.auth_hooks SET enabled = @enabled, fail_open = @fail_open
WHERE id = @id AND tenant_id = @tenant_id;

-- name: DeleteHook :execrows
DELETE FROM tenant.auth_hooks WHERE id = @id AND tenant_id = @tenant_id;
