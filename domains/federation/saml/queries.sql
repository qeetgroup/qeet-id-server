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

-- ==========================================================================
-- IdP-side: Qeet as SAML provider (idp.go)
-- ==========================================================================

-- name: InsertSamlSP :one
INSERT INTO tenant.saml_service_providers
    (tenant_id, name, entity_id, acs_url, name_id_format, name_id_attribute, certificate, status)
VALUES (@tenant_id, @name, @entity_id, @acs_url, @name_id_format, @name_id_attribute, @certificate, @status)
RETURNING id, tenant_id, name, entity_id, acs_url, name_id_format,
          name_id_attribute, certificate, status, created_at, updated_at, last_login_at;

-- name: ListSamlSPs :many
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at
FROM tenant.saml_service_providers WHERE tenant_id = @tenant_id ORDER BY created_at DESC;

-- name: GetSamlSP :one
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at
FROM tenant.saml_service_providers WHERE id = @id AND tenant_id = @tenant_id;

-- name: GetSamlSPByUUID :one
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at
FROM tenant.saml_service_providers WHERE id = @id;

-- name: GetSamlSPByEntityID :one
SELECT id, tenant_id, name, entity_id, acs_url, name_id_format,
       name_id_attribute, certificate, status, created_at, updated_at, last_login_at
FROM tenant.saml_service_providers
WHERE entity_id = @entity_id AND status <> 'disabled' ORDER BY created_at LIMIT 1;

-- name: UpdateSamlSP :one
UPDATE tenant.saml_service_providers SET
    name              = COALESCE(sqlc.narg('name'), name),
    entity_id         = COALESCE(sqlc.narg('entity_id'), entity_id),
    acs_url           = COALESCE(sqlc.narg('acs_url'), acs_url),
    name_id_format    = COALESCE(sqlc.narg('name_id_format'), name_id_format),
    name_id_attribute = COALESCE(sqlc.narg('name_id_attribute'), name_id_attribute),
    certificate       = COALESCE(sqlc.narg('certificate'), certificate),
    status            = COALESCE(sqlc.narg('status'), status),
    updated_at        = NOW()
WHERE id = @id AND tenant_id = @tenant_id
RETURNING id, tenant_id, name, entity_id, acs_url, name_id_format,
          name_id_attribute, certificate, status, created_at, updated_at, last_login_at;

-- name: DeleteSamlSP :execrows
DELETE FROM tenant.saml_service_providers WHERE id = @id AND tenant_id = @tenant_id;

-- name: TouchSamlSPLastLogin :exec
UPDATE tenant.saml_service_providers SET last_login_at = NOW() WHERE id = @id;

-- name: GetUserForIdP :one
SELECT email, display_name, tenant_id FROM "user".users WHERE id = @id AND deleted_at IS NULL;
