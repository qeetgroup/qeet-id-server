-- Queries for the ldap domain.
-- All queries below are STATIC and compiled by sqlc into ./dbgen.
-- getFull (conditional WHERE organization_id) stays hand-written in ldap.go.

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

-- name: LinkExternalIdentity :exec
INSERT INTO account.external_identities (user_id, organization_id, provider, connection_id, subject, email)
VALUES (@user_id, @organization_id, @provider, @connection_id::uuid, @subject, @email)
ON CONFLICT (organization_id, provider, connection_id, subject) DO NOTHING;
