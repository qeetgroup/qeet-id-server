-- Queries for the social domain, compiled by sqlc into ./dbgen.

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

-- name: ExternalIdentityOwner :one
SELECT user_id FROM account.external_identities WHERE id = @id AND organization_id = @organization_id;

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

-- name: EnabledSocialProviderNames :many
SELECT provider FROM organization.social_providers
WHERE organization_id = @organization_id AND enabled ORDER BY provider;

-- ---- An organization's providers (providers.go, social.go) ----

-- name: LockSocialProvider :one
SELECT id, enabled, client_id, apple_team_id, apple_key_id FROM organization.social_providers
WHERE organization_id = @organization_id AND provider = @provider
FOR UPDATE;

-- name: InsertSocialProvider :one
INSERT INTO organization.social_providers
    (organization_id, provider, client_id, client_secret_ct, client_secret_nonce,
     discovery_url, apple_team_id, apple_key_id)
VALUES (@organization_id, @provider, @client_id, @client_secret_ct, @client_secret_nonce,
        NULLIF(@discovery_url::text, ''), NULLIF(@apple_team_id::text, ''), NULLIF(@apple_key_id::text, ''))
RETURNING id, organization_id, provider, client_id, discovery_url, enabled, created_at, apple_team_id, apple_key_id;

-- name: ReplaceSocialProvider :one
-- Keeps whether the provider is switched on, and the stored secret unless
-- replace_secret.
UPDATE organization.social_providers SET
    client_id = @client_id,
    discovery_url = NULLIF(@discovery_url::text, ''),
    client_secret_ct = CASE WHEN @replace_secret::boolean THEN @client_secret_ct ELSE client_secret_ct END,
    client_secret_nonce = CASE WHEN @replace_secret::boolean THEN @client_secret_nonce ELSE client_secret_nonce END,
    apple_team_id = NULLIF(@apple_team_id::text, ''),
    apple_key_id = NULLIF(@apple_key_id::text, '')
WHERE organization_id = @organization_id AND provider = @provider
RETURNING id, organization_id, provider, client_id, discovery_url, enabled, created_at, apple_team_id, apple_key_id;

-- name: UpdateSocialProvider :one
-- Changes the fields given: a NULL keeps one, an empty discovery_url (with
-- set_discovery_url) clears it, and the secret changes only with
-- replace_secret.
UPDATE organization.social_providers SET
    client_id = COALESCE(sqlc.narg('client_id'), client_id),
    discovery_url = CASE WHEN @set_discovery_url::boolean THEN NULLIF(sqlc.narg('discovery_url')::text, '') ELSE discovery_url END,
    enabled = COALESCE(sqlc.narg('enabled'), enabled),
    client_secret_ct = CASE WHEN @replace_secret::boolean THEN @client_secret_ct ELSE client_secret_ct END,
    client_secret_nonce = CASE WHEN @replace_secret::boolean THEN @client_secret_nonce ELSE client_secret_nonce END,
    apple_team_id = COALESCE(sqlc.narg('apple_team_id'), apple_team_id),
    apple_key_id = COALESCE(sqlc.narg('apple_key_id'), apple_key_id)
WHERE id = @id AND organization_id = @organization_id
RETURNING id, organization_id, provider, client_id, discovery_url, enabled, created_at, apple_team_id, apple_key_id;

-- name: DeleteSocialProvider :exec
DELETE FROM organization.social_providers WHERE id = @id AND organization_id = @organization_id;

-- name: SocialProviderDependents :one
-- The people who can sign in to the organization only through provider, and
-- every identity linked to it.
SELECT count(*) FILTER (WHERE
           NOT EXISTS (SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id = ei.user_id)
       AND NOT EXISTS (SELECT 1 FROM auth.passkey_credentials pk WHERE pk.user_id = ei.user_id)
       AND NOT EXISTS (SELECT 1 FROM account.external_identities other
                       WHERE other.user_id = ei.user_id AND other.id <> ei.id
                         AND NOT (other.organization_id = ei.organization_id AND other.provider = ei.provider))
       AND NOT EXISTS (SELECT 1 FROM auth.platform_social_identities ps WHERE ps.user_id = ei.user_id)) AS dependent,
       count(*) AS linked
FROM account.external_identities ei
JOIN account.users u ON u.id = ei.user_id AND u.deleted_at IS NULL
WHERE ei.organization_id = @organization_id AND ei.provider = @provider;

-- name: GetSocialProviderConfig :one
SELECT client_id, client_secret_ct, client_secret_nonce, discovery_url, enabled, apple_team_id, apple_key_id
FROM organization.social_providers
WHERE organization_id = @organization_id AND provider = @provider;

-- name: SocialProviderDiscoveryURL :one
SELECT coalesce(discovery_url, '')::text FROM organization.social_providers
WHERE organization_id = @organization_id AND provider = @provider;

-- ---- Accounts social sign-in finds (social.go, platform.go) ----

-- name: AccountEmail :one
SELECT email FROM account.users WHERE id = @id;

-- name: AccountAddressVerified :one
SELECT (email_verified_at IS NOT NULL)::bool FROM account.users WHERE id = @id;

-- name: AccountByEmail :one
SELECT id FROM account.users WHERE LOWER(email) = LOWER(@email) AND deleted_at IS NULL;

-- name: AdoptAccountAvatar :exec
-- Only when the account has none, never replacing one its holder chose.
UPDATE account.users SET avatar_url = @avatar_url
WHERE id = @id AND (avatar_url IS NULL OR avatar_url = '');

-- name: InsertPlatformAccount :one
-- An organization-less account whose address the platform provider verified.
INSERT INTO account.users (email, display_name, avatar_url, email_verified_at)
VALUES (@email, sqlc.narg('display_name'), sqlc.narg('avatar_url'), NOW())
RETURNING id;

-- ---- Platform link codes (platform.go) ----

-- name: InsertPlatformSocialLinkCode :exec
INSERT INTO auth.platform_social_link_codes (code_hash, user_id, provider, subject, email, expires_at)
VALUES (@code_hash, @user_id, @provider, @subject, sqlc.narg('email'), @expires_at);

-- name: TakePlatformSocialLinkCode :one
DELETE FROM auth.platform_social_link_codes WHERE code_hash = @code_hash
RETURNING user_id, provider, subject, email, expires_at;
