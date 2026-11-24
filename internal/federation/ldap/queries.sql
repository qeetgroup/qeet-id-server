-- Queries for the ldap domain, compiled by sqlc into ./dbgen.

-- name: ListLdapConnections :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
       base_dn, user_filter, email_attribute, name_attribute, status,
       created_at, updated_at, last_login_at, sync_interval_minutes
FROM organization.ldap_connections WHERE organization_id = @organization_id ORDER BY created_at DESC
LIMIT 1001;

-- name: GetLdapConnection :one
SELECT id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
       base_dn, user_filter, email_attribute, name_attribute, status,
       created_at, updated_at, last_login_at, sync_interval_minutes
FROM organization.ldap_connections WHERE id = @id AND organization_id = @organization_id;

-- name: InsertLdapConnection :one
INSERT INTO organization.ldap_connections
    (id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
     bind_password_ct, bind_password_nonce,
     base_dn, user_filter, email_attribute, name_attribute, status, sync_interval_minutes)
VALUES (@id, @organization_id, @name, @server_url, @start_tls, @skip_tls_verify, @bind_dn,
        @bind_password_ct, @bind_password_nonce,
        @base_dn, @user_filter, @email_attribute, @name_attribute, @status, @sync_interval_minutes)
RETURNING id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
          base_dn, user_filter, email_attribute, name_attribute, status,
          created_at, updated_at, last_login_at, sync_interval_minutes;

-- name: GetLdapConnectionWithSecret :one
-- A connection with its sealed bind password. A NULL organization_id reads it
-- by ID alone, for the public sign-in routes, whose path names the connection.
SELECT id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
       base_dn, user_filter, email_attribute, name_attribute, status,
       created_at, updated_at, last_login_at, sync_interval_minutes,
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
    sync_interval_minutes = COALESCE(sqlc.narg('sync_interval_minutes'), sync_interval_minutes),
    updated_at      = NOW()
WHERE id = @id AND organization_id = @organization_id
RETURNING id, organization_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
          base_dn, user_filter, email_attribute, name_attribute, status,
          created_at, updated_at, last_login_at, sync_interval_minutes;

-- name: DeleteLdapConnection :execrows
DELETE FROM organization.ldap_connections WHERE id = @id AND organization_id = @organization_id;

-- name: TouchLdapLastLogin :exec
UPDATE organization.ldap_connections SET last_login_at = NOW() WHERE id = @id;

-- ---- Scheduled sync (sync.go) ----

-- name: ResetLdapSync :exec
UPDATE organization.ldap_connections SET sync_cursor = NULL, full_sync_at = NULL, sync_people = NULL
WHERE id = @id AND organization_id = @organization_id;

-- name: DueLdapSyncs :many
-- Across organizations: the scheduled sync's job.
SELECT id, organization_id FROM organization.ldap_connections
WHERE status = 'active'
  AND (sync_started_at IS NULL OR sync_started_at <= NOW() - make_interval(mins => sync_interval_minutes))
ORDER BY sync_started_at NULLS FIRST, id
LIMIT @max_connections;

-- name: ClaimLdapSync :one
UPDATE organization.ldap_connections SET sync_started_at = NOW()
WHERE id = @id AND organization_id = @organization_id AND status = 'active'
  AND (sync_started_at IS NULL OR sync_started_at <= NOW() - make_interval(mins => sync_interval_minutes))
RETURNING (full_sync_at IS NULL OR sync_cursor IS NULL OR full_sync_at <= NOW() - INTERVAL '1 day')::bool AS full_run,
          COALESCE(sync_cursor, '')::text AS cursor, sync_people, sync_failing;

-- name: FinishLdapSync :exec
UPDATE organization.ldap_connections SET
    sync_succeeded_at = NOW(),
    sync_cursor       = COALESCE(NULLIF(@cursor::text, ''), sync_cursor),
    full_sync_at      = CASE WHEN @full_run::bool THEN NOW() ELSE full_sync_at END,
    sync_people       = CASE WHEN @full_run::bool THEN @people::int ELSE sync_people END,
    sync_failing      = FALSE
WHERE id = @id AND organization_id = @organization_id;

-- name: FailLdapSync :exec
UPDATE organization.ldap_connections SET sync_failing = TRUE
WHERE id = @id AND organization_id = @organization_id;

-- name: LdapLinkedPeople :many
-- Only accounts at home in the organization: a sync never touches another's.
SELECT ei.user_id, ei.subject, COALESCE(ei.email, '')::text AS link_email, u.email, u.status,
       COALESCE(u.suspension_source, '')::text AS suspension_source,
       EXISTS (
           SELECT 1 FROM rbac.user_roles ur
           JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.organization_id = ur.organization_id AND ro.is_system AND ro.name = 'owner'
           WHERE ur.user_id = u.id AND ur.organization_id = @organization_id
           UNION ALL
           SELECT 1 FROM organization.group_members gm
           JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
           JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.organization_id = gr.organization_id AND ro.is_system AND ro.name = 'owner'
           WHERE gm.user_id = u.id AND gm.organization_id = @organization_id
       )::bool AS owner
FROM account.external_identities ei
JOIN account.users u ON u.id = ei.user_id AND u.organization_id = ei.organization_id AND u.deleted_at IS NULL
WHERE ei.organization_id = @organization_id AND ei.provider = 'ldap' AND ei.connection_id = @connection_id::uuid
ORDER BY ei.user_id, ei.subject;

-- name: ReactivateLdapSuspension :execrows
UPDATE account.users SET status = 'active', updated_at = NOW()
WHERE id = @id AND organization_id = @organization_id::uuid AND deleted_at IS NULL
  AND status = 'suspended' AND suspension_source = 'ldap';

-- name: LdapConnectionManagers :many
SELECT u.id FROM account.users u
WHERE u.status = 'active' AND u.deleted_at IS NULL AND u.id IN (
    SELECT ur.user_id FROM rbac.user_roles ur
    JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE ur.organization_id = @organization_id AND p.key = 'connection.write'
    UNION
    SELECT gm.user_id FROM organization.group_members gm
    JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
    JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE gm.organization_id = @organization_id AND p.key = 'connection.write'
)
ORDER BY u.id;
