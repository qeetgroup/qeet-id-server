-- Queries for the oidcsso domain: an organisation's own OpenID Connect
-- identity providers, their sign-in states and one-time login codes, and the
-- identities they link. All queries are STATIC.

-- ==========================================================================
-- Connections (oidcsso.go)
-- ==========================================================================

-- name: InsertOidcConnection :one
INSERT INTO tenant.oidc_connections
    (id, tenant_id, name, issuer, discovery_url, client_id, client_secret_ct, client_secret_nonce,
     scopes, allowed_idp_tenant_ids, email_claim, name_claim, given_name_claim, family_name_claim,
     groups_claim, status)
VALUES (@id, @tenant_id, @name, @issuer, @discovery_url, @client_id, @client_secret_ct, @client_secret_nonce,
        @scopes, @allowed_idp_tenant_ids, @email_claim, @name_claim, @given_name_claim, @family_name_claim,
        @groups_claim, @status)
RETURNING id, tenant_id, name, issuer, discovery_url, client_id, scopes, allowed_idp_tenant_ids,
          email_claim, name_claim, given_name_claim, family_name_claim, groups_claim, status,
          created_at, updated_at, last_login_at;

-- name: ListOidcConnections :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, tenant_id, name, issuer, discovery_url, client_id, scopes, allowed_idp_tenant_ids,
       email_claim, name_claim, given_name_claim, family_name_claim, groups_claim, status,
       created_at, updated_at, last_login_at
FROM tenant.oidc_connections WHERE tenant_id = @tenant_id ORDER BY created_at DESC
LIMIT 1001;

-- name: GetOidcConnection :one
SELECT id, tenant_id, name, issuer, discovery_url, client_id, scopes, allowed_idp_tenant_ids,
       email_claim, name_claim, given_name_claim, family_name_claim, groups_claim, status,
       created_at, updated_at, last_login_at
FROM tenant.oidc_connections WHERE id = @id AND tenant_id = @tenant_id;

-- GetOidcConnectionForSignIn loads a connection and its sealed secret by ID
-- alone: the public sign-in endpoints name it in the path, and it names the
-- organisation.
-- name: GetOidcConnectionForSignIn :one
SELECT id, tenant_id, name, issuer, discovery_url, client_id, scopes, allowed_idp_tenant_ids,
       email_claim, name_claim, given_name_claim, family_name_claim, groups_claim, status,
       created_at, updated_at, last_login_at, client_secret_ct, client_secret_nonce
FROM tenant.oidc_connections WHERE id = @id;

-- name: UpdateOidcConnection :one
UPDATE tenant.oidc_connections SET
    name                   = COALESCE(sqlc.narg('name'), name),
    issuer                 = COALESCE(sqlc.narg('issuer'), issuer),
    discovery_url          = COALESCE(sqlc.narg('discovery_url'), discovery_url),
    client_id              = COALESCE(sqlc.narg('client_id'), client_id),
    client_secret_ct       = COALESCE(sqlc.narg('client_secret_ct')::bytea, client_secret_ct),
    client_secret_nonce    = COALESCE(sqlc.narg('client_secret_nonce')::bytea, client_secret_nonce),
    scopes                 = COALESCE(sqlc.narg('scopes')::text[], scopes),
    allowed_idp_tenant_ids = COALESCE(sqlc.narg('allowed_idp_tenant_ids')::text[], allowed_idp_tenant_ids),
    email_claim            = COALESCE(sqlc.narg('email_claim'), email_claim),
    name_claim             = COALESCE(sqlc.narg('name_claim'), name_claim),
    given_name_claim       = COALESCE(sqlc.narg('given_name_claim'), given_name_claim),
    family_name_claim      = COALESCE(sqlc.narg('family_name_claim'), family_name_claim),
    groups_claim           = COALESCE(sqlc.narg('groups_claim'), groups_claim),
    status                 = COALESCE(sqlc.narg('status'), status),
    updated_at             = NOW()
WHERE id = @id AND tenant_id = @tenant_id
RETURNING id, tenant_id, name, issuer, discovery_url, client_id, scopes, allowed_idp_tenant_ids,
          email_claim, name_claim, given_name_claim, family_name_claim, groups_claim, status,
          created_at, updated_at, last_login_at;

-- name: DeleteOidcConnection :execrows
DELETE FROM tenant.oidc_connections WHERE id = @id AND tenant_id = @tenant_id;

-- name: TouchOidcConnectionLastLogin :exec
UPDATE tenant.oidc_connections SET last_login_at = NOW() WHERE id = @id AND tenant_id = @tenant_id;

-- ==========================================================================
-- Sign-in states and login codes (signin.go)
-- ==========================================================================

-- name: InsertOidcConnectionState :exec
INSERT INTO auth.oidc_connection_states (state_hash, connection_id, code_verifier, nonce_hash, redirect_uri, expires_at, return_to)
VALUES (@state_hash, @connection_id, @code_verifier, @nonce_hash, @redirect_uri, @expires_at, sqlc.narg(return_to));

-- ConsumeOidcConnectionState spends a state as it reads it, so a callback
-- carrying it succeeds at most once.
-- name: ConsumeOidcConnectionState :one
DELETE FROM auth.oidc_connection_states WHERE state_hash = @state_hash
RETURNING connection_id, code_verifier, nonce_hash, redirect_uri, expires_at, return_to;

-- name: DeleteExpiredOidcConnectionStates :exec
DELETE FROM auth.oidc_connection_states WHERE expires_at <= NOW();

-- name: InsertOidcConnectionLoginCode :exec
INSERT INTO auth.oidc_connection_login_codes (code_hash, connection_id, user_id, expires_at)
VALUES (@code_hash, @connection_id, @user_id, @expires_at);

-- name: ConsumeOidcConnectionLoginCode :one
SELECT lc.user_id, lc.expires_at, lc.used_at, c.tenant_id, c.status
FROM auth.oidc_connection_login_codes lc
JOIN tenant.oidc_connections c ON c.id = lc.connection_id
WHERE lc.code_hash = @code_hash
FOR UPDATE OF lc;

-- name: MarkOidcConnectionLoginCodeUsed :exec
UPDATE auth.oidc_connection_login_codes SET used_at = NOW() WHERE code_hash = @code_hash;

-- name: DeleteStaleOidcConnectionLoginCodes :exec
DELETE FROM auth.oidc_connection_login_codes WHERE expires_at <= NOW() - INTERVAL '1 hour';

-- ==========================================================================
-- findOrCreateUser — the same rules as saml and ldap
-- ==========================================================================

-- name: GetExternalIdentityUser :one
SELECT user_id FROM "user".external_identities
WHERE tenant_id = @tenant_id AND provider = @provider AND connection_id = @connection_id::uuid
  AND subject = @subject;

-- name: GetUserByEmail :one
SELECT id FROM "user".users WHERE LOWER(email) = LOWER(@email) AND deleted_at IS NULL;

-- name: InsertUserWithEmail :one
INSERT INTO "user".users (tenant_id, email, email_verified_at, display_name, status)
VALUES (@tenant_id, @email, NOW(), sqlc.narg('display_name'), 'active')
RETURNING id;

-- LinkExternalIdentity links the subject to the connection, or refreshes the
-- profile an existing link holds.
-- name: LinkExternalIdentity :exec
INSERT INTO "user".external_identities (user_id, tenant_id, provider, connection_id, subject, email, metadata)
VALUES (@user_id, @tenant_id, @provider, @connection_id::uuid, @subject, @email, @metadata)
ON CONFLICT (tenant_id, provider, connection_id, subject)
DO UPDATE SET email = EXCLUDED.email, metadata = EXCLUDED.metadata;
