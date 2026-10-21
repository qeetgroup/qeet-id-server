-- Queries for the OIDC domain.
-- All queries are STATIC. Dynamic patterns (buildUpdate etc.) do not exist here.

-- ==========================================================================
-- OIDC clients
-- ==========================================================================

-- name: InsertOIDCClient :one
INSERT INTO auth.oidc_clients (
    tenant_id, client_id, client_secret_hash, type, name,
    redirect_uris, post_logout_uris, grant_types, scopes, backchannel_logout_uri, frontchannel_logout_uri
) VALUES (@tenant_id, @client_id, sqlc.narg('client_secret_hash'), @type, @name,
          @redirect_uris, @post_logout_uris, @grant_types, @scopes,
          NULLIF(@backchannel_logout_uri::text, ''), NULLIF(@frontchannel_logout_uri::text, ''))
RETURNING id, tenant_id, client_id, type, name, redirect_uris,
          post_logout_uris, grant_types, scopes, created_at, pkce_exempt_until, backchannel_logout_uri, frontchannel_logout_uri;

-- pkce_exempt is whether the client's PKCE exemption is in force now.
-- name: GetClientForAuth :one
SELECT id, tenant_id, client_secret_hash, type, grant_types,
       (pkce_exempt_until IS NOT NULL AND pkce_exempt_until > NOW())::bool AS pkce_exempt
FROM auth.oidc_clients WHERE client_id = @client_id;

-- name: GetClientTenantAndScopes :one
SELECT tenant_id, scopes FROM auth.oidc_clients WHERE client_id = @client_id;

-- name: GetClientName :one
SELECT name, tenant_id FROM auth.oidc_clients WHERE client_id = @client_id;

-- name: GetClientRedirectInfo :one
SELECT tenant_id, type, scopes, redirect_uris,
       (pkce_exempt_until IS NOT NULL AND pkce_exempt_until > NOW())::bool AS pkce_exempt
FROM auth.oidc_clients WHERE client_id = @client_id;

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
       post_logout_uris, grant_types, scopes, created_at, pkce_exempt_until, backchannel_logout_uri, frontchannel_logout_uri
FROM auth.oidc_clients WHERE tenant_id = @tenant_id ORDER BY created_at DESC;

-- CountOIDCClientsByTenant counts a tenant's registered applications (relying
-- parties) — the plan "apps" limit check.
-- name: CountOIDCClientsByTenant :one
SELECT COUNT(*) FROM auth.oidc_clients WHERE tenant_id = @tenant_id;

-- name: GetOIDCClient :one
SELECT id, tenant_id, client_id, type, name, redirect_uris,
       post_logout_uris, grant_types, scopes, created_at, pkce_exempt_until, backchannel_logout_uri, frontchannel_logout_uri
FROM auth.oidc_clients WHERE id = @id AND tenant_id = @tenant_id;

-- name: UpdateOIDCClient :one
UPDATE auth.oidc_clients SET
    name             = COALESCE(sqlc.narg('name'), name),
    redirect_uris    = COALESCE(sqlc.narg('redirect_uris'), redirect_uris),
    post_logout_uris = COALESCE(sqlc.narg('post_logout_uris'), post_logout_uris),
    grant_types      = COALESCE(sqlc.narg('grant_types'), grant_types),
    scopes           = COALESCE(sqlc.narg('scopes'), scopes),
    pkce_exempt_until = CASE WHEN @set_pkce_exempt_until::bool
                             THEN sqlc.narg('pkce_exempt_until')::timestamptz
                             ELSE pkce_exempt_until END,
    backchannel_logout_uri = CASE WHEN @set_backchannel_logout_uri::bool
                                  THEN NULLIF(@backchannel_logout_uri::text, '') ELSE backchannel_logout_uri END,
    frontchannel_logout_uri = CASE WHEN @set_frontchannel_logout_uri::bool
                                   THEN NULLIF(@frontchannel_logout_uri::text, '') ELSE frontchannel_logout_uri END
WHERE id = @id AND tenant_id = @tenant_id
RETURNING id, tenant_id, client_id, type, name, redirect_uris,
          post_logout_uris, grant_types, scopes, created_at, pkce_exempt_until, backchannel_logout_uri, frontchannel_logout_uri;

-- name: DeleteOIDCClient :one
DELETE FROM auth.oidc_clients WHERE id = @id AND tenant_id = @tenant_id RETURNING client_id;

-- name: LockOIDCClientForUpdate :one
SELECT id, tenant_id, client_id, type, name, redirect_uris,
       post_logout_uris, grant_types, scopes, created_at, pkce_exempt_until, backchannel_logout_uri, frontchannel_logout_uri
FROM auth.oidc_clients WHERE id = @id AND tenant_id = @tenant_id FOR UPDATE;

-- name: UpdateOIDCClientSecret :exec
UPDATE auth.oidc_clients SET client_secret_hash = @client_secret_hash
WHERE id = @id AND tenant_id = @tenant_id;

-- ==========================================================================
-- Authorization codes
-- ==========================================================================

-- login_session_id is the hosted-login session the code was minted through
-- (NULL when there was none), so signing out of it can spend the code.
-- name: InsertAuthorizationCode :exec
INSERT INTO auth.oidc_authorization_codes (
    code_hash, client_id, user_id, tenant_id, redirect_uri,
    scopes, nonce, code_challenge, code_challenge_method, expires_at, login_session_id, resource, auth_time
) VALUES (@code_hash, @client_id, @user_id, @tenant_id, @redirect_uri,
          @scopes, NULLIF(@nonce,''), NULLIF(@code_challenge,''), NULLIF(@code_challenge_method,''),
          NOW() + INTERVAL '10 minutes', sqlc.narg('login_session_id'), NULLIF(@resource::text,''),
          sqlc.narg('auth_time'));

-- name: ConsumeAuthorizationCode :one
SELECT user_id, tenant_id, redirect_uri, scopes,
       nonce, code_challenge, code_challenge_method, expires_at, used_at, login_session_id, resource, auth_time
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

-- login_session_id is the hosted-login session the grant was started through
-- (NULL when there was none); renewals carry it forward.
-- InsertRefreshToken starts a grant. However often it is renewed, it ends at
-- grant_expires_at: the organisation's maximum session age from now, or the
-- platform's when the organisation sets none. No token outlives the grant.
-- A new grant's first token: its id names the grant (grant_id).
-- name: InsertRefreshToken :exec
INSERT INTO auth.oidc_refresh_tokens
    (id, grant_id, token_hash, client_id, user_id, tenant_id, scopes, expires_at, resource, login_session_id,
     grant_expires_at, authorization_code_hash)
SELECT @id, @id, @token_hash, @client_id, @user_id, @tenant_id, @scopes, LEAST(@expires_at::timestamptz, g.ends),
       sqlc.narg('resource'), sqlc.narg('login_session_id'), g.ends, sqlc.narg('authorization_code_hash')
FROM (
    SELECT NOW() + COALESCE(
        (SELECT sp.session_max_age FROM tenant.security_policies sp WHERE sp.tenant_id = @tenant_id),
        make_interval(secs => @default_max_age_seconds::float8)) AS ends
) g;

-- name: LockRefreshToken :one
SELECT id, client_id, user_id, tenant_id, scopes, expires_at,
       used_at, revoked_at, resource, login_session_id, grant_expires_at, authorization_code_hash, grant_id
FROM auth.oidc_refresh_tokens WHERE token_hash = @token_hash FOR UPDATE;

-- InsertRotatedRefreshToken continues a grant: it keeps the grant's end, and
-- the new token expires no later than it.
-- name: InsertRotatedRefreshToken :one
INSERT INTO auth.oidc_refresh_tokens
    (token_hash, client_id, user_id, tenant_id, scopes, expires_at, resource, login_session_id, grant_expires_at,
     authorization_code_hash, grant_id)
VALUES (@token_hash, @client_id, @user_id, @tenant_id, @scopes,
        LEAST(@expires_at::timestamptz, @grant_expires_at::timestamptz),
        sqlc.narg('resource'), sqlc.narg('login_session_id'), @grant_expires_at::timestamptz,
        sqlc.narg('authorization_code_hash'), sqlc.narg('grant_id'))
RETURNING id;

-- name: MarkRefreshTokenUsed :exec
UPDATE auth.oidc_refresh_tokens SET used_at = NOW(), replaced_by = @new_id WHERE id = @id;

-- name: RevokeRefreshTokenChain :exec
UPDATE auth.oidc_refresh_tokens SET revoked_at = NOW()
WHERE client_id = @client_id AND user_id = @user_id AND revoked_at IS NULL;

-- RevokeGrantFromCode ends the grant redeemed from an authorization code,
-- every rotation of it included: the code was presented a second time.
-- name: RevokeGrantFromCode :execrows
UPDATE auth.oidc_refresh_tokens SET revoked_at = NOW()
WHERE client_id = @client_id AND authorization_code_hash = @authorization_code_hash AND revoked_at IS NULL;

-- RevokeRefreshTokenGrant ends the whole grant (every rotation) the
-- presented token belongs to, when it was issued to the calling client, and
-- returns the rows it ended (none: unknown, another client's, or already ended).
-- name: RevokeRefreshTokenGrant :many
UPDATE auth.oidc_refresh_tokens t SET revoked_at = NOW()
FROM (SELECT p.grant_id FROM auth.oidc_refresh_tokens p
      WHERE p.token_hash = @token_hash AND p.client_id = @client_id) g
WHERE t.grant_id = g.grant_id AND t.client_id = @client_id AND t.revoked_at IS NULL
RETURNING t.id, t.user_id, t.tenant_id, t.grant_id;

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
SELECT client_id, scopes, status, expires_at, tenant_id
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

-- InsertConsentRequest stores an authorization request that has passed the
-- authorize checks and is waiting on the hosted consent screen.
-- name: InsertConsentRequest :one
INSERT INTO auth.oidc_consent_requests (
    login_session_id, user_id, client_id, redirect_uri, scopes, state, nonce,
    code_challenge, code_challenge_method, expires_at, resource
) VALUES (
    @login_session_id, @user_id, @client_id, @redirect_uri, @scopes, @state, @nonce,
    @code_challenge, @code_challenge_method, @expires_at, @resource
)
RETURNING id;

-- GetConsentRequest reads an undecided, unexpired request for the hosted-login
-- session that started it, for the consent screen to show.
-- name: GetConsentRequest :one
SELECT id, user_id, client_id, redirect_uri, scopes, state, nonce, code_challenge, code_challenge_method, resource
FROM auth.oidc_consent_requests
WHERE id = @id AND login_session_id = @login_session_id AND used_at IS NULL AND expires_at > NOW();

-- TakeConsentRequest claims an undecided, unexpired request for its own
-- hosted-login session, once: a second decision finds nothing.
-- name: TakeConsentRequest :one
UPDATE auth.oidc_consent_requests SET used_at = NOW()
WHERE id = @id AND login_session_id = @login_session_id AND used_at IS NULL AND expires_at > NOW()
RETURNING id, user_id, client_id, redirect_uri, scopes, state, nonce, code_challenge, code_challenge_method, resource;

-- GetAccountStanding is what decides whether a user may still be issued tokens:
-- the same suspended-or-deleted rule the first-party refresh applies.
-- name: GetAccountStanding :one
SELECT status, (deleted_at IS NOT NULL)::boolean AS deleted FROM "user".users WHERE id = @id;

-- ==========================================================================
-- Application secret lockout (QTID-215)
-- ==========================================================================

-- GetClientLockedUntil reports a lockout still in force for an application.
-- name: GetClientLockedUntil :one
SELECT locked_until FROM auth.oidc_client_auth_lockouts
WHERE client_row_id = @client_row_id AND locked_until > NOW();

-- RecordClientAuthFailure counts one wrong secret, restarting the count when
-- the window it started has passed, and returns the count.
-- name: RecordClientAuthFailure :one
INSERT INTO auth.oidc_client_auth_lockouts AS l (client_row_id, failures, window_started_at, last_failure_at)
VALUES (@client_row_id, 1, NOW(), NOW())
ON CONFLICT (client_row_id) DO UPDATE SET
    failures = CASE WHEN l.window_started_at <= NOW() - make_interval(secs => @window_seconds::float8)
                    THEN 1 ELSE l.failures + 1 END,
    window_started_at = CASE WHEN l.window_started_at <= NOW() - make_interval(secs => @window_seconds::float8)
                             THEN NOW() ELSE l.window_started_at END,
    last_failure_at = NOW()
RETURNING failures;

-- LockClient starts a lockout and restarts the count, unless one is already
-- in force: only the attempt that starts it gets a row back.
-- name: LockClient :one
UPDATE auth.oidc_client_auth_lockouts
SET locked_until = NOW() + make_interval(secs => @duration_seconds::float8),
    failures = 0, window_started_at = NOW()
WHERE client_row_id = @client_row_id AND (locked_until IS NULL OR locked_until <= NOW())
RETURNING locked_until;

-- ClearClientAuthFailures forgets an application's failures after it
-- authenticates.
-- name: ClearClientAuthFailures :exec
DELETE FROM auth.oidc_client_auth_lockouts WHERE client_row_id = @client_row_id;

-- ListClientAuthFailures is an application's recent wrong-secret attempts,
-- newest first, from the audit log (which never holds the secret).
-- name: ListClientAuthFailures :many
SELECT created_at, COALESCE(host(ip), '')::text AS ip, COALESCE(metadata->>'reason', '')::text AS reason
FROM audit.events
WHERE tenant_id = @tenant_id AND action = 'oidc.client_auth_failed' AND resource_id = @client_row_id
ORDER BY created_at DESC
LIMIT @max_rows;

-- ==========================================================================
-- Resources (RFC 8707 resource indicators, QTID-157)
-- ==========================================================================

-- name: ResourceRegistered :one
SELECT EXISTS (
    SELECT 1 FROM auth.oidc_resources WHERE tenant_id = @tenant_id AND identifier = @identifier
)::bool;

-- name: ListResources :many
SELECT id, tenant_id, identifier, name, server_client_id, created_at
FROM auth.oidc_resources WHERE tenant_id = @tenant_id ORDER BY identifier;

-- name: InsertResource :one
INSERT INTO auth.oidc_resources (tenant_id, identifier, name, server_client_id)
VALUES (@tenant_id, @identifier, @name, sqlc.narg('server_client_id'))
RETURNING id, tenant_id, identifier, name, server_client_id, created_at;

-- name: DeleteResource :one
DELETE FROM auth.oidc_resources WHERE id = @id AND tenant_id = @tenant_id RETURNING identifier;

-- ResourceServedBy reports whether a client serves one of the given resources
-- of its tenant, so it may introspect tokens issued for them.
-- name: ResourceServedBy :one
SELECT EXISTS (
    SELECT 1 FROM auth.oidc_resources
    WHERE tenant_id = @tenant_id AND server_client_id = @client_id AND identifier = ANY(@identifiers::text[])
)::bool;

-- GetUserinfo is what userinfo and the ID token may say about a live account
-- (QTID-165). locale is read from the profile metadata when set.
-- name: GetUserinfo :one
SELECT email, email_verified_at, phone, phone_verified_at, display_name, avatar_url, updated_at,
       COALESCE(metadata->>'locale', '')::text AS locale
FROM "user".users WHERE id = @id AND deleted_at IS NULL AND status = 'active';

-- ==========================================================================
-- Sign-out notices (OpenID Connect Back- and Front-Channel Logout, QTID-166)
-- ==========================================================================

-- SessionClients is every application that holds a code or a grant from a
-- hosted-login session, with where it hears of a sign-out.
-- name: SessionClients :many
SELECT c.client_id, c.tenant_id, COALESCE(c.backchannel_logout_uri, '')::text AS backchannel_logout_uri,
       COALESCE(c.frontchannel_logout_uri, '')::text AS frontchannel_logout_uri
FROM auth.oidc_clients c
WHERE c.client_id IN (
    SELECT t.client_id FROM auth.oidc_refresh_tokens t WHERE t.login_session_id = @login_session_id
    UNION
    SELECT a.client_id FROM auth.oidc_authorization_codes a WHERE a.login_session_id = @login_session_id
)
ORDER BY c.client_id;

-- name: InsertLogoutDelivery :exec
INSERT INTO auth.oidc_logout_deliveries (tenant_id, client_id, uri, logout_token)
VALUES (@tenant_id, @client_id, @uri, @logout_token);

-- ClaimLogoutDeliveries takes due notices for one delivery pass, pushing them
-- back so a crashed pass's are retried, not lost.
-- name: ClaimLogoutDeliveries :many
UPDATE auth.oidc_logout_deliveries d SET next_attempt_at = NOW() + INTERVAL '5 minutes'
WHERE d.id IN (
    SELECT id FROM auth.oidc_logout_deliveries
    WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= NOW()
    ORDER BY next_attempt_at LIMIT @max_rows FOR UPDATE SKIP LOCKED
)
RETURNING d.id, d.tenant_id, d.client_id, d.uri, d.logout_token, d.attempts;

-- name: MarkLogoutDelivered :exec
UPDATE auth.oidc_logout_deliveries SET delivered_at = NOW(), attempts = attempts + 1, last_error = ''
WHERE id = @id;

-- name: MarkLogoutDeliveryFailed :exec
UPDATE auth.oidc_logout_deliveries
SET attempts = attempts + 1, last_error = @last_error,
    next_attempt_at = NOW() + make_interval(secs => @retry_in_seconds::float8),
    failed_at = CASE WHEN @final::bool THEN NOW() END
WHERE id = @id;
