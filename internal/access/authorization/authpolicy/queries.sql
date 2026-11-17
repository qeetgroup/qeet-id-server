-- Queries for the authpolicy domain.
-- Both GET and UPSERT are fully static; converted to sqlc.
-- Dynamic partial-update (future) would remain hand-written.

-- name: GetAuthPolicy :one
SELECT * FROM organization.auth_policy WHERE organization_id = @organization_id;

-- name: UpsertAuthPolicy :one
INSERT INTO organization.auth_policy
    (organization_id, password_enabled, password_min_length, password_require_uppercase,
     password_require_number, password_require_symbol, magic_link_enabled,
     magic_link_ttl_minutes, passkey_enabled, otp_email_enabled, otp_sms_enabled,
     self_registration_enabled, remember_device_enabled, remember_device_days,
     lockout_threshold, lockout_window_minutes, lockout_duration_minutes, updated_at)
VALUES (@organization_id, @password_enabled, @password_min_length, @password_require_uppercase,
        @password_require_number, @password_require_symbol, @magic_link_enabled,
        @magic_link_ttl_minutes, @passkey_enabled, @otp_email_enabled, @otp_sms_enabled,
        @self_registration_enabled, @remember_device_enabled, @remember_device_days,
        sqlc.narg(lockout_threshold), sqlc.narg(lockout_window_minutes), sqlc.narg(lockout_duration_minutes), NOW())
ON CONFLICT (organization_id) DO UPDATE SET
    password_enabled          = EXCLUDED.password_enabled,
    password_min_length       = EXCLUDED.password_min_length,
    password_require_uppercase= EXCLUDED.password_require_uppercase,
    password_require_number   = EXCLUDED.password_require_number,
    password_require_symbol   = EXCLUDED.password_require_symbol,
    magic_link_enabled        = EXCLUDED.magic_link_enabled,
    magic_link_ttl_minutes    = EXCLUDED.magic_link_ttl_minutes,
    passkey_enabled           = EXCLUDED.passkey_enabled,
    otp_email_enabled         = EXCLUDED.otp_email_enabled,
    otp_sms_enabled           = EXCLUDED.otp_sms_enabled,
    self_registration_enabled = EXCLUDED.self_registration_enabled,
    remember_device_enabled   = EXCLUDED.remember_device_enabled,
    remember_device_days      = EXCLUDED.remember_device_days,
    lockout_threshold         = EXCLUDED.lockout_threshold,
    lockout_window_minutes    = EXCLUDED.lockout_window_minutes,
    lockout_duration_minutes  = EXCLUDED.lockout_duration_minutes,
    updated_at                = NOW()
RETURNING *;

-- name: SignInMethodUsage :one
-- The organization's live accounts, those with a password and with a passkey,
-- and of each those with no other way in: no other credential and no linked
-- identity.
WITH people AS (
    SELECT EXISTS (SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id = u.id) AS password,
           EXISTS (SELECT 1 FROM auth.passkey_credentials pk WHERE pk.user_id = u.id) AS passkey,
           EXISTS (SELECT 1 FROM account.external_identities ei WHERE ei.user_id = u.id)
             OR EXISTS (SELECT 1 FROM auth.platform_social_identities ps WHERE ps.user_id = u.id) AS linked
    FROM account.users u
    WHERE u.organization_id = @organization_id::uuid AND u.deleted_at IS NULL
)
SELECT count(*)::int AS people,
       count(*) FILTER (WHERE password)::int AS with_password,
       count(*) FILTER (WHERE password AND NOT passkey AND NOT linked)::int AS only_password,
       count(*) FILTER (WHERE passkey)::int AS with_passkey,
       count(*) FILTER (WHERE passkey AND NOT password AND NOT linked)::int AS only_passkey
FROM people;

-- name: SocialProviderUsage :many
-- Per social provider the organization set up: the live accounts linked to it,
-- and those who can sign in only through it.
SELECT sp.provider,
       count(DISTINCT ei.user_id)::int AS linked,
       count(DISTINCT ei.user_id) FILTER (WHERE
           NOT EXISTS (SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id = ei.user_id)
       AND NOT EXISTS (SELECT 1 FROM auth.passkey_credentials pk WHERE pk.user_id = ei.user_id)
       AND NOT EXISTS (SELECT 1 FROM account.external_identities other
                        WHERE other.user_id = ei.user_id AND other.id <> ei.id
                          AND NOT (other.organization_id = ei.organization_id AND other.provider = ei.provider))
       AND NOT EXISTS (SELECT 1 FROM auth.platform_social_identities ps WHERE ps.user_id = ei.user_id))::int AS only
FROM organization.social_providers sp
LEFT JOIN account.external_identities ei ON ei.organization_id = sp.organization_id AND ei.provider = sp.provider
     AND EXISTS (SELECT 1 FROM account.users u WHERE u.id = ei.user_id AND u.deleted_at IS NULL)
WHERE sp.organization_id = @organization_id
GROUP BY sp.provider
ORDER BY sp.provider;

-- name: HasActiveSSOConnection :one
-- Whether the organization has an active SAML, LDAP or OpenID Connect connection to
-- sign in through.
SELECT (
    EXISTS (SELECT 1 FROM organization.saml_connections s WHERE s.organization_id = sqlc.arg(organization_id)::uuid AND s.status = 'active')
    OR EXISTS (SELECT 1 FROM organization.ldap_connections l WHERE l.organization_id = sqlc.arg(organization_id)::uuid AND l.status = 'active')
    OR EXISTS (SELECT 1 FROM organization.oidc_connections o WHERE o.organization_id = sqlc.arg(organization_id)::uuid AND o.status = 'active')
)::boolean;
