-- Queries for the ldap domain.
-- All queries below are STATIC and compiled by sqlc into ./dbgen.
-- getFull (conditional WHERE tenant_id) stays hand-written in ldap.go.

-- name: InsertLdapConnection :one
INSERT INTO tenant.ldap_connections
    (tenant_id, name, server_url, start_tls, skip_tls_verify, bind_dn, bind_password,
     base_dn, user_filter, email_attribute, name_attribute, status)
VALUES (@tenant_id, @name, @server_url, @start_tls, @skip_tls_verify, @bind_dn, @bind_password,
        @base_dn, @user_filter, @email_attribute, @name_attribute, @status)
RETURNING id, tenant_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
          base_dn, user_filter, email_attribute, name_attribute, status,
          created_at, updated_at, last_login_at;

-- name: ListLdapConnections :many
SELECT id, tenant_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
       base_dn, user_filter, email_attribute, name_attribute, status,
       created_at, updated_at, last_login_at
FROM tenant.ldap_connections WHERE tenant_id = @tenant_id ORDER BY created_at DESC;

-- name: GetLdapConnection :one
SELECT id, tenant_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
       base_dn, user_filter, email_attribute, name_attribute, status,
       created_at, updated_at, last_login_at
FROM tenant.ldap_connections WHERE id = @id AND tenant_id = @tenant_id;

-- name: UpdateLdapConnection :one
UPDATE tenant.ldap_connections SET
    name            = COALESCE(sqlc.narg('name'), name),
    server_url      = COALESCE(sqlc.narg('server_url'), server_url),
    start_tls       = COALESCE(sqlc.narg('start_tls'), start_tls),
    skip_tls_verify = COALESCE(sqlc.narg('skip_tls_verify'), skip_tls_verify),
    bind_dn         = COALESCE(sqlc.narg('bind_dn'), bind_dn),
    bind_password   = COALESCE(sqlc.narg('bind_password'), bind_password),
    base_dn         = COALESCE(sqlc.narg('base_dn'), base_dn),
    user_filter     = COALESCE(sqlc.narg('user_filter'), user_filter),
    email_attribute = COALESCE(sqlc.narg('email_attribute'), email_attribute),
    name_attribute  = COALESCE(sqlc.narg('name_attribute'), name_attribute),
    status          = COALESCE(sqlc.narg('status'), status),
    updated_at      = NOW()
WHERE id = @id AND tenant_id = @tenant_id
RETURNING id, tenant_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
          base_dn, user_filter, email_attribute, name_attribute, status,
          created_at, updated_at, last_login_at;

-- name: DeleteLdapConnection :execrows
DELETE FROM tenant.ldap_connections WHERE id = @id AND tenant_id = @tenant_id;

-- name: TouchLdapLastLogin :exec
UPDATE tenant.ldap_connections SET last_login_at = NOW() WHERE id = @id;

-- name: GetExternalIdentityUser :one
SELECT user_id FROM "user".external_identities
WHERE tenant_id = @tenant_id AND provider = @provider AND subject = @subject;

-- name: GetUserByEmail :one
SELECT id FROM "user".users WHERE LOWER(email) = LOWER(@email) AND deleted_at IS NULL;

-- name: InsertUserWithEmail :one
INSERT INTO "user".users (tenant_id, email, email_verified_at, display_name, status)
VALUES (@tenant_id, @email, NOW(), sqlc.narg('display_name'), 'active')
RETURNING id;

-- name: LinkExternalIdentity :exec
INSERT INTO "user".external_identities (user_id, tenant_id, provider, subject, email)
VALUES (@user_id, @tenant_id, @provider, @subject, @email)
ON CONFLICT (tenant_id, provider, subject) DO NOTHING;
