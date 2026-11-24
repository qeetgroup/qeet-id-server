-- Queries for the oidcsso domain: an organization's own OpenID Connect
-- identity providers. All queries are STATIC.

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
