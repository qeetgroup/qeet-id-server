-- Queries for the auth-hooks domain.
-- All queries are static; no dynamic SQL in this domain.

-- name: ListHooks :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, trigger, url, enabled, fail_open, created_at,
       last_called_at, last_outcome, last_status_code, call_count, skip_count, deny_count
FROM tenant.auth_hooks WHERE tenant_id = $1 ORDER BY created_at DESC
LIMIT 1001;

-- RecordHookCall counts one sign-in's call to a hook: its outcome (allowed,
-- denied or skipped), and the status the hook answered when it answered.
-- name: RecordHookCall :exec
UPDATE tenant.auth_hooks
SET last_called_at = NOW(), last_outcome = @outcome, last_status_code = sqlc.narg('status_code'),
    call_count = call_count + 1,
    skip_count = skip_count + CASE WHEN @outcome = 'skipped' THEN 1 ELSE 0 END,
    deny_count = deny_count + CASE WHEN @outcome = 'denied' THEN 1 ELSE 0 END
WHERE id = @id AND tenant_id = @tenant_id;

-- name: GetHookForCall :one
-- A hook's URL and secret, to call it outside a sign-in.
SELECT id, url, secret, secret_ct, secret_nonce, fail_open
FROM tenant.auth_hooks WHERE id = @id AND tenant_id = @tenant_id;

-- name: SetHookEndpoint :execrows
-- A new URL, a new secret, or both, for one of the tenant's hooks.
UPDATE tenant.auth_hooks
SET url = COALESCE(sqlc.narg('url'), url),
    secret = CASE WHEN sqlc.narg('secret_ct')::bytea IS NULL THEN secret ELSE '' END,
    secret_ct = COALESCE(sqlc.narg('secret_ct')::bytea, secret_ct),
    secret_nonce = COALESCE(sqlc.narg('secret_nonce')::bytea, secret_nonce),
    encryption_version = CASE WHEN sqlc.narg('secret_ct')::bytea IS NULL THEN encryption_version ELSE 1 END
WHERE id = @id AND tenant_id = @tenant_id;

-- UpdateHook sets whichever of enabled and fail_open are given, keeping the
-- other, and returns both as stored.
-- name: UpdateHook :one
UPDATE tenant.auth_hooks
SET enabled = COALESCE(sqlc.narg('enabled')::boolean, enabled),
    fail_open = COALESCE(sqlc.narg('fail_open')::boolean, fail_open)
WHERE id = @id AND tenant_id = @tenant_id
RETURNING enabled, fail_open;

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
