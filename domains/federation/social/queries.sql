-- Queries for the social domain.
-- All queries are STATIC and compiled by sqlc into ./dbgen.

-- name: UpsertSocialProvider :one
INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret, discovery_url)
VALUES (@tenant_id, @provider, @client_id, @client_secret, NULLIF(@discovery_url,''))
ON CONFLICT (tenant_id, provider) DO UPDATE SET
    client_id     = EXCLUDED.client_id,
    client_secret = EXCLUDED.client_secret,
    discovery_url = EXCLUDED.discovery_url,
    enabled       = TRUE
RETURNING id, tenant_id, provider, client_id, discovery_url, enabled, created_at;

-- name: ListSocialProviders :many
SELECT id, tenant_id, provider, client_id, discovery_url, enabled, created_at
FROM tenant.social_providers WHERE tenant_id = @tenant_id ORDER BY provider;

-- name: ListExternalIdentities :many
SELECT ei.id, ei.user_id, ei.tenant_id, ei.provider, ei.subject, ei.email, ei.linked_at
FROM "user".external_identities ei
JOIN "user".users u ON u.id = ei.user_id
WHERE ei.user_id = @user_id AND ei.tenant_id = @tenant_id AND u.deleted_at IS NULL
ORDER BY ei.linked_at DESC;

-- name: DeleteExternalIdentity :execrows
DELETE FROM "user".external_identities WHERE id = @id AND tenant_id = @tenant_id;

-- name: GetTenantIDBySlug :one
SELECT id FROM tenant.tenants WHERE slug = @slug;

-- name: LoadSocialProvider :one
SELECT client_id, client_secret, discovery_url, enabled
FROM tenant.social_providers WHERE tenant_id = @tenant_id AND provider = @provider;

-- name: InsertSocialOAuthState :exec
INSERT INTO auth.social_oauth_states
    (state_hash, tenant_id, provider, code_verifier, redirect_uri, return_to, expires_at)
VALUES (@state_hash, @tenant_id, @provider, @code_verifier, @redirect_uri, @return_to, @expires_at);

-- name: ConsumeSocialOAuthState :one
DELETE FROM auth.social_oauth_states WHERE state_hash = @state_hash
RETURNING tenant_id, provider, code_verifier, redirect_uri, return_to, expires_at;

-- name: InsertSocialLoginCode :exec
INSERT INTO auth.social_login_codes (code_hash, user_id, tenant_id, expires_at)
VALUES (@code_hash, @user_id, @tenant_id, @expires_at);

-- name: EnabledSocialProviderNames :many
SELECT provider FROM tenant.social_providers
WHERE tenant_id = @tenant_id AND enabled ORDER BY provider;

-- name: ConsumeSocialLoginCode :one
SELECT user_id, tenant_id, expires_at, used_at
FROM auth.social_login_codes WHERE code_hash = @code_hash FOR UPDATE;

-- name: MarkSocialLoginCodeUsed :exec
UPDATE auth.social_login_codes SET used_at = NOW() WHERE code_hash = @code_hash;

-- ==========================================================================
-- findOrCreateUser — same cross-schema "user" pattern as ldap/saml
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
