-- Queries for the social domain.
-- All queries are STATIC and compiled by sqlc into ./dbgen.

-- name: ListSocialProviders :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, provider, client_id, discovery_url, enabled, created_at, apple_team_id, apple_key_id
FROM organization.social_providers WHERE organization_id = @organization_id ORDER BY provider
LIMIT 1001;

-- name: ListExternalIdentities :many
SELECT ei.id, ei.user_id, ei.organization_id, ei.provider, ei.subject, ei.email, ei.linked_at
FROM account.external_identities ei
JOIN account.users u ON u.id = ei.user_id
WHERE ei.user_id = @user_id AND ei.organization_id = @organization_id AND u.deleted_at IS NULL
ORDER BY ei.linked_at DESC;

-- name: DeleteExternalIdentity :execrows
DELETE FROM account.external_identities WHERE id = @id AND organization_id = @organization_id;

-- ListExternalIdentitiesForUser is the self-service variant: scoped to the
-- caller's own user id across every organization, so an org-less user can still see
-- the social logins linked to their account.
-- name: ListExternalIdentitiesForUser :many
SELECT ei.id, ei.user_id, ei.organization_id, ei.provider, ei.subject, ei.email, ei.linked_at
FROM account.external_identities ei
JOIN account.users u ON u.id = ei.user_id
WHERE ei.user_id = @user_id AND u.deleted_at IS NULL
ORDER BY ei.linked_at DESC;

-- DeleteExternalIdentityForUser unlinks scoped to the owner (not an organization), so
-- a user can remove their own social login before joining any org.
-- name: DeleteExternalIdentityForUser :execrows
DELETE FROM account.external_identities WHERE id = @id AND user_id = @user_id;

-- ---- Platform (organization-less) connected social accounts ----

-- UpsertPlatformSocialIdentity records the identity for a console account. On
-- conflict the identity already belongs to a user (ownership never changes here
-- — the link path checks ownership first); we just refresh the email.
-- name: UpsertPlatformSocialIdentity :exec
INSERT INTO auth.platform_social_identities (user_id, provider, subject, email)
VALUES (@user_id, @provider, @subject, @email)
ON CONFLICT (provider, subject) DO UPDATE SET email = EXCLUDED.email;

-- GetPlatformSocialIdentityOwner returns the user a provider identity is already
-- linked to (pgx.ErrNoRows = not linked yet). Used to reject cross-account links.
-- name: GetPlatformSocialIdentityOwner :one
SELECT user_id FROM auth.platform_social_identities
WHERE provider = @provider AND subject = @subject;

-- name: ListPlatformSocialIdentitiesForUser :many
SELECT id, user_id, provider, subject, email, linked_at
FROM auth.platform_social_identities
WHERE user_id = @user_id
ORDER BY linked_at DESC;

-- name: DeletePlatformSocialIdentityForUser :execrows
DELETE FROM auth.platform_social_identities WHERE id = @id AND user_id = @user_id;

-- name: GetOrganizationIDBySlug :one
SELECT id FROM organization.organizations WHERE slug = @slug;

-- name: InsertSocialOAuthState :exec
INSERT INTO auth.oauth_states
    (state_hash, kind, organization_id, provider, code_verifier, redirect_uri, return_to, expires_at, nonce_hash)
VALUES (@state_hash, 'social', @organization_id::uuid, @provider::text, @code_verifier, @redirect_uri,
        NULLIF(@return_to::text, ''), @expires_at, sqlc.narg('nonce_hash'));

-- name: ConsumeSocialOAuthState :one
DELETE FROM auth.oauth_states WHERE state_hash = @state_hash AND kind = 'social'
RETURNING organization_id::uuid AS organization_id, provider::text AS provider, code_verifier, redirect_uri,
          COALESCE(return_to, '')::text AS return_to, expires_at, nonce_hash;

-- name: InsertSocialLoginCode :exec
INSERT INTO auth.login_codes (code_hash, kind, user_id, organization_id, provider, expires_at)
VALUES (@code_hash, 'social', @user_id, @organization_id::uuid, @provider::text, @expires_at);

-- name: EnabledSocialProviderNames :many
SELECT provider FROM organization.social_providers
WHERE organization_id = @organization_id AND enabled ORDER BY provider;

-- name: ConsumeSocialLoginCode :one
-- With whether the provider that issued the code is on: one since deleted finds no row.
SELECT lc.user_id, p.organization_id, lc.expires_at, lc.used_at, p.enabled
FROM auth.login_codes lc
JOIN organization.social_providers p ON p.organization_id = lc.organization_id AND p.provider = lc.provider
WHERE lc.code_hash = @code_hash AND lc.kind = 'social'
FOR UPDATE OF lc;

-- name: MarkSocialLoginCodeUsed :exec
UPDATE auth.login_codes SET used_at = NOW() WHERE code_hash = @code_hash AND organization_id = @organization_id::uuid;

-- ==========================================================================
-- findOrCreateUser — same cross-schema account pattern as ldap/saml
-- ==========================================================================

-- name: GetExternalIdentityUser :one
-- A social identity names no connection; a single sign-on connection's links,
-- whose provider a social one could be named after, are not looked at.
SELECT user_id FROM account.external_identities
WHERE organization_id = @organization_id AND provider = @provider AND subject = @subject
  AND connection_id IS NULL;

-- name: GetUserByEmail :one
SELECT id FROM account.users WHERE LOWER(email) = LOWER(@email) AND deleted_at IS NULL;

-- name: InsertUserWithEmail :one
INSERT INTO account.users (organization_id, email, email_verified_at, display_name, status)
VALUES (@organization_id, @email, NOW(), sqlc.narg('display_name'), 'active')
RETURNING id;

-- name: LinkExternalIdentity :exec
INSERT INTO account.external_identities (user_id, organization_id, provider, subject, email)
VALUES (@user_id, @organization_id, @provider, @subject, @email)
ON CONFLICT (organization_id, provider, connection_id, subject) DO NOTHING;
