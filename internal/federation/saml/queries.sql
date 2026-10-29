-- Queries for the saml domain.
-- Covers both saml.go (SP-side Service) and idp.go (IdP-side IdP struct).
-- All queries are STATIC.

-- ==========================================================================
-- SP-side: external IdP connections (saml.go)
-- ==========================================================================

-- name: InsertSamlConnection :one
INSERT INTO tenant.saml_connections
    (tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate, email_attribute, name_attribute, status)
VALUES (@tenant_id, @name, @idp_entity_id, @idp_sso_url, @idp_certificate, @email_attribute, @name_attribute, @status)
RETURNING id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate,
          email_attribute, name_attribute, status, created_at, updated_at, last_login_at;

-- name: ListSamlConnections :many
SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate,
       email_attribute, name_attribute, status, created_at, updated_at, last_login_at
FROM tenant.saml_connections WHERE tenant_id = @tenant_id ORDER BY created_at DESC;

-- name: GetSamlConnection :one
SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate,
       email_attribute, name_attribute, status, created_at, updated_at, last_login_at
FROM tenant.saml_connections WHERE id = @id AND tenant_id = @tenant_id;

-- name: GetSamlConnectionByID :one
SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate,
       email_attribute, name_attribute, status, created_at, updated_at, last_login_at
FROM tenant.saml_connections WHERE id = @id;

-- name: UpdateSamlConnection :one
UPDATE tenant.saml_connections SET
    name            = COALESCE(sqlc.narg('name'), name),
    idp_entity_id   = COALESCE(sqlc.narg('idp_entity_id'), idp_entity_id),
    idp_sso_url     = COALESCE(sqlc.narg('idp_sso_url'), idp_sso_url),
    idp_certificate = COALESCE(sqlc.narg('idp_certificate'), idp_certificate),
    email_attribute = COALESCE(sqlc.narg('email_attribute'), email_attribute),
    name_attribute  = COALESCE(sqlc.narg('name_attribute'), name_attribute),
    status          = COALESCE(sqlc.narg('status'), status),
    updated_at      = NOW()
WHERE id = @id AND tenant_id = @tenant_id
RETURNING id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate,
          email_attribute, name_attribute, status, created_at, updated_at, last_login_at;

-- name: DeleteSamlConnection :execrows
DELETE FROM tenant.saml_connections WHERE id = @id AND tenant_id = @tenant_id;

-- name: TouchSamlLastLogin :exec
UPDATE tenant.saml_connections SET last_login_at = NOW() WHERE id = @id;

-- The groups attribute isn't in the connection queries above, so it is read
-- and written on its own.

-- name: GetSamlGroupsAttribute :one
SELECT groups_attribute FROM tenant.saml_connections WHERE id = @id AND tenant_id = @tenant_id;

-- name: ListSamlGroupsAttributes :many
SELECT id, groups_attribute FROM tenant.saml_connections WHERE tenant_id = @tenant_id;

-- name: SetSamlGroupsAttribute :exec
UPDATE tenant.saml_connections SET groups_attribute = @groups_attribute, updated_at = NOW()
WHERE id = @id AND tenant_id = @tenant_id;

-- ==========================================================================
-- SP-side: the IdP signing certificates a connection trusts (certificates.go)
-- ==========================================================================

-- name: LockSamlConnection :one
SELECT id FROM tenant.saml_connections WHERE id = @id AND tenant_id = @tenant_id FOR UPDATE;

-- name: ListSamlCertificates :many
SELECT id, tenant_id, connection_id, certificate, source, created_at
FROM tenant.saml_connection_certificates
WHERE connection_id = @connection_id AND tenant_id = @tenant_id
ORDER BY created_at, id;

-- name: ListSamlCertificatesForTenant :many
SELECT id, tenant_id, connection_id, certificate, source, created_at
FROM tenant.saml_connection_certificates
WHERE tenant_id = @tenant_id
ORDER BY created_at, id;

-- name: InsertSamlCertificate :one
INSERT INTO tenant.saml_connection_certificates (tenant_id, connection_id, certificate, source)
VALUES (@tenant_id, @connection_id, @certificate, @source)
RETURNING id, tenant_id, connection_id, certificate, source, created_at;

-- name: DeleteSamlCertificate :exec
DELETE FROM tenant.saml_connection_certificates
WHERE id = @id AND connection_id = @connection_id AND tenant_id = @tenant_id;

-- name: DeleteSamlCertificates :exec
DELETE FROM tenant.saml_connection_certificates
WHERE connection_id = @connection_id AND tenant_id = @tenant_id;

-- name: SetSamlCertificateSource :exec
UPDATE tenant.saml_connection_certificates SET source = @source
WHERE id = @id AND tenant_id = @tenant_id;

-- name: SyncSamlPrimaryCertificate :exec
UPDATE tenant.saml_connections c SET
    idp_certificate = (
        SELECT k.certificate FROM tenant.saml_connection_certificates k
        WHERE k.connection_id = c.id AND k.tenant_id = c.tenant_id
        ORDER BY k.created_at, k.id LIMIT 1
    ),
    updated_at = NOW()
WHERE c.id = @id AND c.tenant_id = @tenant_id;

-- ==========================================================================
-- SP-side: a connection's IdP metadata (metadata.go)
-- ==========================================================================

-- name: GetSamlMetadataSource :one
SELECT metadata_url, metadata_refreshed_at, metadata_error
FROM tenant.saml_connections WHERE id = @id AND tenant_id = @tenant_id;

-- name: ListSamlMetadataSources :many
SELECT id, metadata_url, metadata_refreshed_at, metadata_error
FROM tenant.saml_connections WHERE tenant_id = @tenant_id;

-- name: LockSamlMetadataSource :one
SELECT idp_entity_id, idp_sso_url, metadata_url FROM tenant.saml_connections
WHERE id = @id AND tenant_id = @tenant_id FOR UPDATE;

-- name: SetSamlIdPFromMetadata :exec
UPDATE tenant.saml_connections SET
    idp_sso_url           = @idp_sso_url,
    metadata_url          = sqlc.narg('metadata_url'),
    metadata_checked_at   = NOW(),
    metadata_refreshed_at = NOW(),
    metadata_error        = NULL,
    updated_at            = CASE WHEN idp_sso_url <> @idp_sso_url THEN NOW() ELSE updated_at END
WHERE id = @id AND tenant_id = @tenant_id;

-- name: SetSamlMetadataError :exec
UPDATE tenant.saml_connections SET metadata_checked_at = NOW(), metadata_error = @metadata_error
WHERE id = @id AND tenant_id = @tenant_id;

-- name: ListSamlMetadataDue :many
SELECT id, tenant_id, metadata_url::text AS metadata_url FROM tenant.saml_connections
WHERE metadata_url IS NOT NULL AND (metadata_checked_at IS NULL OR metadata_checked_at < @checked_before)
ORDER BY metadata_checked_at NULLS FIRST, id
LIMIT @max_rows;

-- ==========================================================================
-- SP-side: the key pair a connection's IdP encrypts assertions to (encryption.go)
-- ==========================================================================

-- name: GetSamlConnectionKey :one
SELECT certificate, key_ct, key_nonce FROM tenant.saml_connection_keys
WHERE connection_id = @connection_id AND tenant_id = @tenant_id;

-- name: InsertSamlConnectionKey :exec
INSERT INTO tenant.saml_connection_keys (connection_id, tenant_id, certificate, key_ct, key_nonce)
VALUES (@connection_id, @tenant_id, @certificate, @key_ct, @key_nonce)
ON CONFLICT (connection_id) DO NOTHING;

-- ==========================================================================
-- SAML login codes (ExchangeLogin + ACS handler)
-- ==========================================================================

-- name: InsertSamlLoginCode :exec
INSERT INTO auth.saml_login_codes (code_hash, user_id, tenant_id, expires_at)
VALUES (@code_hash, @user_id, @tenant_id, @expires_at);

-- name: ConsumeSamlLoginCode :one
SELECT user_id, tenant_id, expires_at, used_at
FROM auth.saml_login_codes WHERE code_hash = @code_hash FOR UPDATE;

-- name: MarkSamlLoginCodeUsed :exec
UPDATE auth.saml_login_codes SET used_at = NOW() WHERE code_hash = @code_hash;

-- ==========================================================================
-- findOrCreateUser — same pattern as ldap (cross-schema "user" tables)
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

-- name: LinkExternalIdentity :exec
INSERT INTO "user".external_identities (user_id, tenant_id, provider, connection_id, subject, email)
VALUES (@user_id, @tenant_id, @provider, @connection_id::uuid, @subject, @email)
ON CONFLICT (tenant_id, provider, connection_id, subject) DO NOTHING;

-- ==========================================================================
-- IdP-side: Qeet as SAML provider (idp.go)
-- ==========================================================================

-- name: InsertSamlSP :one
INSERT INTO tenant.saml_service_providers
    (tenant_id, name, entity_id, acs_url, name_id_format, name_id_attribute, certificate, status,
     attributes, assignment_required, require_signed_requests, encrypt_assertions)
VALUES (@tenant_id, @name, @entity_id, @acs_url, @name_id_format, @name_id_attribute, @certificate, @status,
        @attributes, @assignment_required, @require_signed_requests, @encrypt_assertions)
RETURNING id, tenant_id, name, entity_id, acs_url, name_id_format,
          name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
          attributes, assignment_required, require_signed_requests, encrypt_assertions;

-- name: ListSamlSPs :many
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes, assignment_required, require_signed_requests, encrypt_assertions
FROM tenant.saml_service_providers WHERE tenant_id = @tenant_id ORDER BY created_at DESC;

-- name: GetSamlSP :one
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes, assignment_required, require_signed_requests, encrypt_assertions
FROM tenant.saml_service_providers WHERE id = @id AND tenant_id = @tenant_id;

-- GetSamlSPForUpdate reads a service provider and holds it until the
-- transaction ends, so a change is checked against what it changes.
-- name: GetSamlSPForUpdate :one
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes, assignment_required, require_signed_requests, encrypt_assertions
FROM tenant.saml_service_providers WHERE id = @id AND tenant_id = @tenant_id
FOR UPDATE;

-- name: GetSamlSPByEntityID :one
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes, assignment_required, require_signed_requests, encrypt_assertions
FROM tenant.saml_service_providers
WHERE tenant_id = @tenant_id AND entity_id = @entity_id AND status <> 'disabled';

-- name: IsTenantActive :one
SELECT EXISTS (
    SELECT 1 FROM tenant.tenants WHERE id = @id AND status = 'active' AND deleted_at IS NULL
);

-- name: UpdateSamlSP :one
UPDATE tenant.saml_service_providers SET
    name                = COALESCE(sqlc.narg('name'), name),
    entity_id           = COALESCE(sqlc.narg('entity_id'), entity_id),
    acs_url             = COALESCE(sqlc.narg('acs_url'), acs_url),
    name_id_format      = COALESCE(sqlc.narg('name_id_format'), name_id_format),
    name_id_attribute   = COALESCE(sqlc.narg('name_id_attribute'), name_id_attribute),
    certificate         = COALESCE(sqlc.narg('certificate'), certificate),
    status              = COALESCE(sqlc.narg('status'), status),
    attributes          = COALESCE(sqlc.narg('attributes'), attributes),
    assignment_required = COALESCE(sqlc.narg('assignment_required'), assignment_required),
    require_signed_requests = COALESCE(sqlc.narg('require_signed_requests'), require_signed_requests),
    encrypt_assertions  = COALESCE(sqlc.narg('encrypt_assertions'), encrypt_assertions),
    updated_at          = NOW()
WHERE id = @id AND tenant_id = @tenant_id
RETURNING id, tenant_id, name, entity_id, acs_url, name_id_format,
          name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
          attributes, assignment_required, require_signed_requests, encrypt_assertions;

-- name: DeleteSamlSP :execrows
DELETE FROM tenant.saml_service_providers WHERE id = @id AND tenant_id = @tenant_id;

-- name: TouchSamlSPLastLogin :exec
UPDATE tenant.saml_service_providers SET last_login_at = NOW() WHERE id = @id;

-- name: GetUserForIdP :one
SELECT email, display_name, tenant_id, status, metadata FROM "user".users WHERE id = @id AND deleted_at IS NULL;

-- ==========================================================================
-- IdP-side: what an assertion says about a person (idp_attributes.go)
-- ==========================================================================

-- GetIdPNameParts is a person's given and family name from their
-- organisation's directory profiles, the most recently updated one naming each.
-- name: GetIdPNameParts :one
SELECT COALESCE((SELECT p.profile->>'first_name' FROM tenant.directory_profiles p
                 WHERE p.tenant_id = @tenant_id AND p.user_id = @user_id
                   AND jsonb_typeof(p.profile->'first_name') = 'string'
                 ORDER BY p.updated_at DESC LIMIT 1), '')::text AS given_name,
       COALESCE((SELECT p.profile->>'last_name' FROM tenant.directory_profiles p
                 WHERE p.tenant_id = @tenant_id AND p.user_id = @user_id
                   AND jsonb_typeof(p.profile->'last_name') = 'string'
                 ORDER BY p.updated_at DESC LIMIT 1), '')::text AS family_name;

-- name: ListIdPUserGroupNames :many
SELECT g.name
FROM tenant.group_members gm
JOIN tenant.groups g ON g.id = gm.group_id AND g.tenant_id = gm.tenant_id
WHERE gm.tenant_id = @tenant_id AND gm.user_id = @user_id
ORDER BY g.name;

-- ListIdPUserRoleNames is the names of the roles a person holds in the
-- organisation, directly or through a group.
-- name: ListIdPUserRoleNames :many
SELECT DISTINCT ro.name
FROM rbac.roles ro
WHERE ro.tenant_id = @tenant_id AND ro.id IN (
    SELECT ur.role_id FROM rbac.user_roles ur
    WHERE ur.tenant_id = @tenant_id AND ur.user_id = @user_id
    UNION
    SELECT gr.role_id FROM tenant.group_members gm
    JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
    WHERE gm.tenant_id = @tenant_id AND gm.user_id = @user_id
)
ORDER BY ro.name;

-- name: GetSamlPersistentID :one
SELECT name_id FROM tenant.saml_idp_persistent_ids
WHERE tenant_id = @tenant_id AND sp_id = @sp_id AND user_id = @user_id;

-- InsertSamlPersistentID keeps name_id as the person's persistent NameID at
-- the service provider, or returns the one another sign-in kept first.
-- name: InsertSamlPersistentID :one
INSERT INTO tenant.saml_idp_persistent_ids (tenant_id, sp_id, user_id, name_id)
VALUES (@tenant_id, @sp_id, @user_id, @name_id)
ON CONFLICT (tenant_id, sp_id, user_id) DO UPDATE SET name_id = saml_idp_persistent_ids.name_id
RETURNING name_id;

-- ==========================================================================
-- IdP-side: who may sign in to a service provider (idp_assignment.go)
-- ==========================================================================

-- IsAssignedToSamlSP reports whether a person is assigned to the service
-- provider, themselves or through a group they belong to.
-- name: IsAssignedToSamlSP :one
SELECT (EXISTS (
    SELECT 1 FROM tenant.saml_sp_user_assignments ua
    WHERE ua.tenant_id = @tenant_id AND ua.sp_id = @sp_id AND ua.user_id = @user_id
) OR EXISTS (
    SELECT 1 FROM tenant.saml_sp_group_assignments ga
    JOIN tenant.group_members gm ON gm.group_id = ga.group_id AND gm.tenant_id = ga.tenant_id
    WHERE ga.tenant_id = @tenant_id AND ga.sp_id = @sp_id AND gm.user_id = @user_id
))::bool AS assigned;

-- IsSamlAssignableUser reports whether the organisation is the account's home,
-- the only people its service providers sign in.
-- name: IsSamlAssignableUser :one
SELECT EXISTS (
    SELECT 1 FROM "user".users WHERE id = @user_id AND tenant_id = @tenant_id AND deleted_at IS NULL
)::bool;

-- name: IsSamlAssignableGroup :one
SELECT EXISTS (
    SELECT 1 FROM tenant.groups WHERE id = @group_id AND tenant_id = @tenant_id
)::bool;

-- name: ListSamlSPUserAssignments :many
SELECT a.user_id, u.email, u.display_name, a.assigned_at, a.assigned_by
FROM tenant.saml_sp_user_assignments a
JOIN "user".users u ON u.id = a.user_id
WHERE a.tenant_id = @tenant_id AND a.sp_id = @sp_id
ORDER BY a.assigned_at, a.user_id;

-- name: ListSamlSPGroupAssignments :many
SELECT a.group_id, g.name, a.assigned_at, a.assigned_by
FROM tenant.saml_sp_group_assignments a
JOIN tenant.groups g ON g.id = a.group_id AND g.tenant_id = a.tenant_id
WHERE a.tenant_id = @tenant_id AND a.sp_id = @sp_id
ORDER BY a.assigned_at, a.group_id;

-- name: InsertSamlSPUserAssignment :execrows
INSERT INTO tenant.saml_sp_user_assignments (tenant_id, sp_id, user_id, assigned_by)
VALUES (@tenant_id, @sp_id, @user_id, sqlc.narg('assigned_by'))
ON CONFLICT DO NOTHING;

-- name: DeleteSamlSPUserAssignment :execrows
DELETE FROM tenant.saml_sp_user_assignments
WHERE tenant_id = @tenant_id AND sp_id = @sp_id AND user_id = @user_id;

-- name: InsertSamlSPGroupAssignment :execrows
INSERT INTO tenant.saml_sp_group_assignments (tenant_id, sp_id, group_id, assigned_by)
VALUES (@tenant_id, @sp_id, @group_id, sqlc.narg('assigned_by'))
ON CONFLICT DO NOTHING;

-- name: DeleteSamlSPGroupAssignment :execrows
DELETE FROM tenant.saml_sp_group_assignments
WHERE tenant_id = @tenant_id AND sp_id = @sp_id AND group_id = @group_id;
