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
    (tenant_id, name, entity_id, acs_url, name_id_format, name_id_attribute, certificate, status, attributes)
VALUES (@tenant_id, @name, @entity_id, @acs_url, @name_id_format, @name_id_attribute, @certificate, @status, @attributes)
RETURNING id, tenant_id, name, entity_id, acs_url, name_id_format,
          name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
          attributes;

-- name: ListSamlSPs :many
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes
FROM tenant.saml_service_providers WHERE tenant_id = @tenant_id ORDER BY created_at DESC;

-- name: GetSamlSP :one
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes
FROM tenant.saml_service_providers WHERE id = @id AND tenant_id = @tenant_id;

-- GetSamlSPForUpdate reads a service provider and holds it until the
-- transaction ends, so a change is checked against what it changes.
-- name: GetSamlSPForUpdate :one
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes
FROM tenant.saml_service_providers WHERE id = @id AND tenant_id = @tenant_id
FOR UPDATE;

-- name: GetSamlSPByEntityID :one
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
       attributes
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
    updated_at          = NOW()
WHERE id = @id AND tenant_id = @tenant_id
RETURNING id, tenant_id, name, entity_id, acs_url, name_id_format,
          name_id_attribute, certificate, status, created_at, updated_at, last_login_at,
          attributes;

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
