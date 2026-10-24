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

-- ListEnabledSignInHooks returns the tenant's enabled sign-in hooks with their
-- secrets, oldest first: the order Run calls them in.
-- name: ListEnabledSignInHooks :many
SELECT id, url, secret, secret_ct, secret_nonce, fail_open
FROM tenant.auth_hooks
WHERE tenant_id = @tenant_id AND enabled AND trigger = 'post_login'
ORDER BY created_at, id;

-- SealHookSecret replaces a hook's plaintext secret with its encrypted form.
-- name: SealHookSecret :exec
UPDATE tenant.auth_hooks
SET secret = '', secret_ct = @secret_ct, secret_nonce = @secret_nonce, encryption_version = 1
WHERE id = @id AND tenant_id = @tenant_id AND secret_ct IS NULL;
