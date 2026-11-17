-- Queries for the oidcsso domain: an organization's own OpenID Connect
-- identity providers, their sign-in states and one-time login codes, and the
-- identities they link. All queries are STATIC.

-- ==========================================================================
-- Connections (oidcsso.go)
-- ==========================================================================

-- name: InsertOidcConnection :one
INSERT INTO organization.oidc_connections
    (id, organization_id, name, issuer, discovery_url, client_id, client_secret_ct, client_secret_nonce,
     scopes, allowed_idp_tenant_ids, email_claim, name_claim, given_name_claim, family_name_claim,
     groups_claim, status)
VALUES (@id, @organization_id, @name, @issuer, @discovery_url, @client_id, @client_secret_ct, @client_secret_nonce,
        @scopes, @allowed_idp_tenant_ids, @email_claim, @name_claim, @given_name_claim, @family_name_claim,
        @groups_claim, @status)
RETURNING id, organization_id, name, issuer, discovery_url, client_id, scopes, allowed_idp_tenant_ids,
          email_claim, name_claim, given_name_claim, family_name_claim, groups_claim, status,
          created_at, updated_at, last_login_at;

-- name: ListOidcConnections :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, name, issuer, discovery_url, client_id, scopes, allowed_idp_tenant_ids,
       email_claim, name_claim, given_name_claim, family_name_claim, groups_claim, status,
       created_at, updated_at, last_login_at
FROM organization.oidc_connections WHERE organization_id = @organization_id ORDER BY created_at DESC
LIMIT 1001;

-- name: GetOidcConnection :one
SELECT id, organization_id, name, issuer, discovery_url, client_id, scopes, allowed_idp_tenant_ids,
       email_claim, name_claim, given_name_claim, family_name_claim, groups_claim, status,
       created_at, updated_at, last_login_at
FROM organization.oidc_connections WHERE id = @id AND organization_id = @organization_id;

-- GetOidcConnectionForSignIn loads a connection and its sealed secret by ID
-- alone: the public sign-in endpoints name it in the path, and it names the
-- organization.
-- name: GetOidcConnectionForSignIn :one
SELECT id, organization_id, name, issuer, discovery_url, client_id, scopes, allowed_idp_tenant_ids,
       email_claim, name_claim, given_name_claim, family_name_claim, groups_claim, status,
       created_at, updated_at, last_login_at, client_secret_ct, client_secret_nonce
FROM organization.oidc_connections WHERE id = @id;

-- name: UpdateOidcConnection :one
UPDATE organization.oidc_connections SET
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
WHERE id = @id AND organization_id = @organization_id
RETURNING id, organization_id, name, issuer, discovery_url, client_id, scopes, allowed_idp_tenant_ids,
          email_claim, name_claim, given_name_claim, family_name_claim, groups_claim, status,
          created_at, updated_at, last_login_at;

-- name: DeleteOidcConnection :execrows
DELETE FROM organization.oidc_connections WHERE id = @id AND organization_id = @organization_id;

-- name: TouchOidcConnectionLastLogin :exec
UPDATE organization.oidc_connections SET last_login_at = NOW() WHERE id = @id AND organization_id = @organization_id;

-- ==========================================================================
-- Sign-in states and login codes (signin.go)
-- ==========================================================================

-- name: InsertOidcConnectionState :exec
INSERT INTO auth.oauth_states
    (state_hash, kind, organization_id, connection_id, code_verifier, nonce_hash, redirect_uri, expires_at, return_to)
VALUES (@state_hash, 'oidc_connection', @organization_id::uuid, @connection_id::uuid, @code_verifier, @nonce_hash::text,
        @redirect_uri, @expires_at, sqlc.narg(return_to));

-- ConsumeOidcConnectionState spends a state the connection issued as it reads
-- it, so a callback carrying it succeeds at most once.
-- name: ConsumeOidcConnectionState :one
DELETE FROM auth.oauth_states
WHERE state_hash = @state_hash AND kind = 'oidc_connection'
  AND organization_id = @organization_id::uuid AND connection_id = @connection_id::uuid
RETURNING code_verifier, nonce_hash::text AS nonce_hash, redirect_uri, expires_at, return_to;

-- name: InsertOidcConnectionLoginCode :exec
INSERT INTO auth.login_codes (code_hash, kind, user_id, organization_id, connection_id, expires_at)
VALUES (@code_hash, 'oidc_connection', @user_id, @organization_id::uuid, @connection_id::uuid, @expires_at);

-- name: ConsumeOidcConnectionLoginCode :one
SELECT lc.user_id, lc.expires_at, lc.used_at, c.organization_id, c.status
FROM auth.login_codes lc
JOIN organization.oidc_connections c ON c.organization_id = lc.organization_id AND c.id = lc.connection_id
WHERE lc.code_hash = @code_hash AND lc.kind = 'oidc_connection'
FOR UPDATE OF lc;

-- name: MarkOidcConnectionLoginCodeUsed :exec
UPDATE auth.login_codes SET used_at = NOW() WHERE code_hash = @code_hash AND organization_id = @organization_id::uuid;

-- ==========================================================================
-- findOrCreateUser — the same rules as saml and ldap
-- ==========================================================================

-- name: GetExternalIdentityUser :one
SELECT user_id FROM account.external_identities
WHERE organization_id = @organization_id AND provider = @provider AND connection_id = @connection_id::uuid
  AND subject = @subject;

-- name: GetUserByEmail :one
SELECT id FROM account.users WHERE LOWER(email) = LOWER(@email) AND deleted_at IS NULL;

-- name: InsertUserWithEmail :one
INSERT INTO account.users (organization_id, email, email_verified_at, display_name, status)
VALUES (@organization_id, @email, NOW(), sqlc.narg('display_name'), 'active')
RETURNING id;

-- LinkExternalIdentity links the subject to the connection, or refreshes the
-- profile an existing link holds.
-- name: LinkExternalIdentity :exec
INSERT INTO account.external_identities (user_id, organization_id, provider, connection_id, subject, email, metadata)
VALUES (@user_id, @organization_id, @provider, @connection_id::uuid, @subject, @email, @metadata)
ON CONFLICT (organization_id, provider, connection_id, subject)
DO UPDATE SET email = EXCLUDED.email, metadata = EXCLUDED.metadata;
