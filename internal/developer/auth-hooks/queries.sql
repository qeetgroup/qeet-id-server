-- Queries for the auth-hooks domain.
-- All queries are static; no dynamic SQL in this domain.

-- GetActiveHook retrieves the first enabled post_login hook for a tenant,
-- used by Run() during the login flow.
-- name: GetActiveHook :one
SELECT url, secret, fail_open FROM tenant.auth_hooks
WHERE tenant_id = $1 AND enabled AND trigger = 'post_login'
ORDER BY created_at LIMIT 1;

-- name: CreateHook :one
INSERT INTO tenant.auth_hooks (tenant_id, url, secret, fail_open)
VALUES (@tenant_id, @url, @secret, @fail_open)
RETURNING id, trigger, url, enabled, fail_open, created_at;

-- name: ListHooks :many
SELECT id, trigger, url, enabled, fail_open, created_at
FROM tenant.auth_hooks WHERE tenant_id = $1 ORDER BY created_at DESC;

-- name: UpdateHook :execrows
UPDATE tenant.auth_hooks SET enabled = @enabled, fail_open = @fail_open
WHERE id = @id AND tenant_id = @tenant_id;

-- name: DeleteHook :execrows
DELETE FROM tenant.auth_hooks WHERE id = @id AND tenant_id = @tenant_id;
