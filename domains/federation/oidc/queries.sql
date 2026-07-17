-- Queries for the OIDC domain.
-- All queries are STATIC. Dynamic patterns (buildUpdate etc.) do not exist here.

-- ==========================================================================
-- OIDC clients
-- ==========================================================================

-- name: InsertOIDCClient :one
INSERT INTO auth.oidc_clients (
    tenant_id, client_id, client_secret_hash, type, name,
    redirect_uris, post_logout_uris, grant_types, scopes
) VALUES (@tenant_id, @client_id, sqlc.narg('client_secret_hash'), @type, @name,
          @redirect_uris, @post_logout_uris, @grant_types, @scopes)
RETURNING id, tenant_id, client_id, type, name, redirect_uris,
          post_logout_uris, grant_types, scopes, created_at;

-- name: GetClientForAuth :one
SELECT client_secret_hash, type, grant_types
FROM auth.oidc_clients WHERE client_id = @client_id;

-- name: GetClientTenantAndScopes :one
SELECT tenant_id, scopes FROM auth.oidc_clients WHERE client_id = @client_id;

-- name: GetClientName :one
SELECT name, tenant_id FROM auth.oidc_clients WHERE client_id = @client_id;

-- name: GetClientRedirectInfo :one
SELECT tenant_id, scopes, redirect_uris FROM auth.oidc_clients WHERE client_id = @client_id;

-- name: GetClientPostLogoutURIs :one
SELECT post_logout_uris FROM auth.oidc_clients WHERE client_id = @client_id;

-- name: GetClientGrantTypes :one
SELECT grant_types FROM auth.oidc_clients WHERE client_id = @client_id;

-- name: ListShadowAICandidates :many
SELECT c.id, c.client_id, c.name, c.grant_types, c.created_at,
       COALESCE(g.live, 0)::bigint AS live_grants
FROM auth.oidc_clients c
LEFT JOIN (
    SELECT client_id, COUNT(*) AS live
    FROM auth.oidc_refresh_tokens
    WHERE revoked_at IS NULL AND expires_at > NOW()
    GROUP BY client_id
) g ON g.client_id = c.client_id
WHERE c.tenant_id = @tenant_id
  AND c.reviewed_at IS NULL
  AND c.grant_types && @machine_grant_types::text[]
ORDER BY live_grants DESC, c.created_at DESC;

-- name: ReviewOIDCClient :execrows
UPDATE auth.oidc_clients SET reviewed_at = NOW(), reviewed_by = @reviewed_by
WHERE id = @id AND tenant_id = @tenant_id;

-- name: ListOIDCClients :many
SELECT id, tenant_id, client_id, type, name, redirect_uris,
       post_logout_uris, grant_types, scopes, created_at
FROM auth.oidc_clients WHERE tenant_id = @tenant_id ORDER BY created_at DESC;

-- name: GetOIDCClient :one
SELECT id, tenant_id, client_id, type, name, redirect_uris,
       post_logout_uris, grant_types, scopes, created_at
FROM auth.oidc_clients WHERE id = @id AND tenant_id = @tenant_id;

-- name: UpdateOIDCClient :one
UPDATE auth.oidc_clients SET
    name             = COALESCE(sqlc.narg('name'), name),
    redirect_uris    = COALESCE(sqlc.narg('redirect_uris'), redirect_uris),
    post_logout_uris = COALESCE(sqlc.narg('post_logout_uris'), post_logout_uris),
    grant_types      = COALESCE(sqlc.narg('grant_types'), grant_types),
    scopes           = COALESCE(sqlc.narg('scopes'), scopes)
WHERE id = @id AND tenant_id = @tenant_id
RETURNING id, tenant_id, client_id, type, name, redirect_uris,
          post_logout_uris, grant_types, scopes, created_at;

-- name: DeleteOIDCClient :one
DELETE FROM auth.oidc_clients WHERE id = @id AND tenant_id = @tenant_id RETURNING client_id;

-- name: LockOIDCClientForUpdate :one
SELECT id, tenant_id, client_id, type, name, redirect_uris,
       post_logout_uris, grant_types, scopes, created_at
FROM auth.oidc_clients WHERE id = @id AND tenant_id = @tenant_id FOR UPDATE;

-- name: UpdateOIDCClientSecret :exec
UPDATE auth.oidc_clients SET client_secret_hash = @client_secret_hash
WHERE id = @id AND tenant_id = @tenant_id;

-- ==========================================================================
-- Authorization codes
-- ==========================================================================

-- name: InsertAuthorizationCode :exec
INSERT INTO auth.oidc_authorization_codes (
    code_hash, client_id, user_id, tenant_id, redirect_uri,
    scopes, nonce, code_challenge, code_challenge_method, expires_at
) VALUES (@code_hash, @client_id, @user_id, @tenant_id, @redirect_uri,
          @scopes, NULLIF(@nonce,''), NULLIF(@code_challenge,''), NULLIF(@code_challenge_method,''),
          NOW() + INTERVAL '10 minutes');

-- name: ConsumeAuthorizationCode :one
SELECT user_id, tenant_id, redirect_uri, scopes,
       nonce, code_challenge, code_challenge_method, expires_at, used_at
FROM auth.oidc_authorization_codes
WHERE code_hash = @code_hash AND client_id = @client_id
FOR UPDATE;

-- name: MarkAuthorizationCodeUsed :exec
UPDATE auth.oidc_authorization_codes SET used_at = NOW() WHERE code_hash = @code_hash;

-- ==========================================================================
-- Consents
-- ==========================================================================

-- name: GetConsent :one
SELECT scopes FROM auth.oidc_consents WHERE user_id = @user_id AND client_id = @client_id;

-- name: UpsertConsent :exec
INSERT INTO auth.oidc_consents (user_id, client_id, scopes, granted_at)
VALUES (@user_id, @client_id, @scopes, NOW())
ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = NOW();

-- ==========================================================================
-- Refresh tokens
-- ==========================================================================

-- name: InsertRefreshToken :exec
INSERT INTO auth.oidc_refresh_tokens
    (token_hash, client_id, user_id, tenant_id, scopes, expires_at, resource)
VALUES (@token_hash, @client_id, @user_id, @tenant_id, @scopes, @expires_at, sqlc.narg('resource'));

-- name: LockRefreshToken :one
SELECT id, client_id, user_id, tenant_id, scopes, expires_at,
       used_at, revoked_at, resource
FROM auth.oidc_refresh_tokens WHERE token_hash = @token_hash FOR UPDATE;

-- name: InsertRotatedRefreshToken :one
INSERT INTO auth.oidc_refresh_tokens
    (token_hash, client_id, user_id, tenant_id, scopes, expires_at, resource)
VALUES (@token_hash, @client_id, @user_id, @tenant_id, @scopes, @expires_at, sqlc.narg('resource'))
RETURNING id;

-- name: MarkRefreshTokenUsed :exec
UPDATE auth.oidc_refresh_tokens SET used_at = NOW(), replaced_by = @new_id WHERE id = @id;

-- name: RevokeRefreshTokenChain :exec
UPDATE auth.oidc_refresh_tokens SET revoked_at = NOW()
WHERE client_id = @client_id AND user_id = @user_id AND revoked_at IS NULL;

-- name: RevokeRefreshTokenByHash :exec
UPDATE auth.oidc_refresh_tokens SET revoked_at = NOW()
WHERE token_hash = @token_hash AND client_id = @client_id AND revoked_at IS NULL;

-- name: GetRefreshTokenForIntrospect :one
SELECT client_id, user_id, tenant_id, scopes, issued_at, expires_at, used_at, revoked_at
FROM auth.oidc_refresh_tokens WHERE token_hash = @token_hash;

-- name: ListGrants :many
SELECT t.id, t.client_id, t.user_id, COALESCE(u.email, '') AS user_email,
       t.scopes, t.issued_at, t.expires_at
FROM auth.oidc_refresh_tokens t
LEFT JOIN "user".users u ON u.id = t.user_id
WHERE t.tenant_id = @tenant_id
  AND t.revoked_at IS NULL AND t.replaced_by IS NULL AND t.expires_at > NOW()
ORDER BY t.issued_at DESC;

-- name: GetGrantForRevoke :one
SELECT client_id, user_id FROM auth.oidc_refresh_tokens
WHERE id = @id AND tenant_id = @tenant_id;

-- name: RevokeGrantChain :exec
UPDATE auth.oidc_refresh_tokens SET revoked_at = NOW()
WHERE client_id = @client_id AND user_id = @user_id AND tenant_id = @tenant_id
  AND revoked_at IS NULL;

-- ==========================================================================
-- Device Authorization (RFC 8628)
-- ==========================================================================

-- name: InsertDeviceCode :exec
INSERT INTO auth.oidc_device_codes (
    device_code_hash, user_code, client_id, tenant_id, scopes,
    interval_seconds, expires_at
) VALUES (@device_code_hash, @user_code, @client_id, @tenant_id, @scopes,
          @interval_seconds, NOW() + INTERVAL '10 minutes');

-- name: GetDeviceByUserCode :one
SELECT client_id, scopes, status, expires_at
FROM auth.oidc_device_codes WHERE user_code = @user_code;

-- name: LockDeviceByUserCode :one
SELECT id, client_id, tenant_id, scopes, status, expires_at
FROM auth.oidc_device_codes WHERE user_code = @user_code FOR UPDATE;

-- name: DenyDevice :exec
UPDATE auth.oidc_device_codes SET status = 'denied' WHERE id = @id;

-- name: CheckUserInDeviceTenant :one
SELECT EXISTS(SELECT 1 FROM "user".users WHERE id = @id AND tenant_id = @tenant_id);

-- name: ApproveDevice :exec
UPDATE auth.oidc_device_codes SET status = 'authorized', user_id = @user_id, approved_at = NOW()
WHERE id = @id;

-- name: LockDeviceByCode :one
SELECT id, client_id, tenant_id, user_id, scopes, status,
       interval_seconds, last_polled_at, expires_at, consumed_at
FROM auth.oidc_device_codes WHERE device_code_hash = @device_code_hash FOR UPDATE;

-- name: TouchDevicePollTime :exec
UPDATE auth.oidc_device_codes SET last_polled_at = NOW() WHERE id = @id;

-- name: ConsumeDeviceCode :exec
UPDATE auth.oidc_device_codes SET consumed_at = NOW() WHERE id = @id;

-- name: ListDevices :many
SELECT d.id, d.client_id, d.user_code, d.status, d.user_id,
       COALESCE(u.email, '') AS user_email, d.scopes,
       d.created_at, d.expires_at, d.last_polled_at
FROM auth.oidc_device_codes d
LEFT JOIN "user".users u ON u.id = d.user_id
WHERE d.tenant_id = @tenant_id
ORDER BY d.created_at DESC;

-- name: RevokeDevice :one
UPDATE auth.oidc_device_codes SET status = 'denied'
WHERE id = @id AND tenant_id = @tenant_id
RETURNING client_id, user_code;

-- ==========================================================================
-- CIBA (OpenID Connect Client-Initiated Backchannel Authentication)
-- ==========================================================================

-- name: GetUserByEmailInTenant :one
SELECT id FROM "user".users
WHERE tenant_id = @tenant_id AND LOWER(email) = LOWER(@email) AND deleted_at IS NULL;

-- name: InsertCIBARequest :exec
INSERT INTO auth.oidc_ciba_requests (
    auth_req_id_hash, client_id, tenant_id, user_id, scopes,
    binding_message, interval_seconds, expires_at
) VALUES (@auth_req_id_hash, @client_id, @tenant_id, @user_id, @scopes,
          sqlc.narg('binding_message'), @interval_seconds, NOW() + INTERVAL '10 minutes');

-- name: ListPendingCIBA :many
SELECT id, client_id, scopes, binding_message, created_at, expires_at
FROM auth.oidc_ciba_requests
WHERE user_id = @user_id AND status = 'pending' AND expires_at > NOW()
ORDER BY created_at DESC;

-- name: LockCIBARequest :one
SELECT user_id, status, expires_at
FROM auth.oidc_ciba_requests WHERE id = @id FOR UPDATE;

-- name: DenyCIBARequest :exec
UPDATE auth.oidc_ciba_requests SET status = 'denied' WHERE id = @id;

-- name: ApproveCIBARequest :exec
UPDATE auth.oidc_ciba_requests SET status = 'authorized', approved_at = NOW() WHERE id = @id;

-- name: LockCIBARequestByHash :one
SELECT id, client_id, tenant_id, user_id, scopes, status,
       interval_seconds, last_polled_at, expires_at, consumed_at
FROM auth.oidc_ciba_requests WHERE auth_req_id_hash = @auth_req_id_hash FOR UPDATE;

-- name: TouchCIBAPollTime :exec
UPDATE auth.oidc_ciba_requests SET last_polled_at = NOW() WHERE id = @id;

-- name: ConsumeCIBARequest :exec
UPDATE auth.oidc_ciba_requests SET consumed_at = NOW() WHERE id = @id;
