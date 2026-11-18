-- Queries for the ldap domain, compiled by sqlc into ./dbgen.

-- name: ListLdapConnections :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
       base_dn, user_filter, email_attribute, name_attribute, status,
       created_at, updated_at, last_login_at
FROM organization.ldap_connections WHERE organization_id = @organization_id ORDER BY created_at DESC
LIMIT 1001;

-- name: GetLdapConnection :one
SELECT id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
       base_dn, user_filter, email_attribute, name_attribute, status,
       created_at, updated_at, last_login_at
FROM organization.ldap_connections WHERE id = @id AND organization_id = @organization_id;

-- name: InsertLdapConnection :one
INSERT INTO organization.ldap_connections
    (id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
     bind_password_ct, bind_password_nonce,
     base_dn, user_filter, email_attribute, name_attribute, status)
VALUES (@id, @organization_id, @name, @server_url, @start_tls, @skip_tls_verify, @bind_dn,
        @bind_password_ct, @bind_password_nonce,
        @base_dn, @user_filter, @email_attribute, @name_attribute, @status)
RETURNING id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
          base_dn, user_filter, email_attribute, name_attribute, status,
          created_at, updated_at, last_login_at;

-- name: GetLdapConnectionWithSecret :one
-- A connection with its sealed bind password. A NULL organization_id reads it
-- by ID alone, for the public sign-in routes, whose path names the connection.
SELECT id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
       base_dn, user_filter, email_attribute, name_attribute, status,
       created_at, updated_at, last_login_at,
       bind_password_ct, bind_password_nonce
FROM organization.ldap_connections
WHERE id = @id AND (sqlc.narg('organization_id')::uuid IS NULL OR organization_id = sqlc.narg('organization_id'));

-- name: SetLdapBindPassword :exec
UPDATE organization.ldap_connections
SET bind_password_ct = @bind_password_ct, bind_password_nonce = @bind_password_nonce, updated_at = NOW()
WHERE id = @id AND organization_id = @organization_id;

-- name: UpdateLdapConnection :one
UPDATE organization.ldap_connections SET
    name            = COALESCE(sqlc.narg('name'), name),
    server_url      = COALESCE(sqlc.narg('server_url'), server_url),
    start_tls       = COALESCE(sqlc.narg('start_tls'), start_tls),
    skip_tls_verify = COALESCE(sqlc.narg('skip_tls_verify'), skip_tls_verify),
    bind_dn         = COALESCE(sqlc.narg('bind_dn'), bind_dn),
    base_dn         = COALESCE(sqlc.narg('base_dn'), base_dn),
    user_filter     = COALESCE(sqlc.narg('user_filter'), user_filter),
    email_attribute = COALESCE(sqlc.narg('email_attribute'), email_attribute),
    name_attribute  = COALESCE(sqlc.narg('name_attribute'), name_attribute),
    status          = COALESCE(sqlc.narg('status'), status),
    updated_at      = NOW()
WHERE id = @id AND organization_id = @organization_id
RETURNING id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
          base_dn, user_filter, email_attribute, name_attribute, status,
          created_at, updated_at, last_login_at;

-- name: DeleteLdapConnection :execrows
DELETE FROM organization.ldap_connections WHERE id = @id AND organization_id = @organization_id;

-- name: TouchLdapLastLogin :exec
UPDATE organization.ldap_connections SET last_login_at = NOW() WHERE id = @id;
