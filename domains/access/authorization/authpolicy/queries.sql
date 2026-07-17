-- Queries for the authpolicy domain.
-- Both GET and UPSERT are fully static; converted to sqlc.
-- Dynamic partial-update (future) would remain hand-written.

-- name: GetAuthPolicy :one
SELECT * FROM tenant.auth_policy WHERE tenant_id = @tenant_id;

-- name: UpsertAuthPolicy :one
INSERT INTO tenant.auth_policy
    (tenant_id, password_enabled, password_min_length, password_require_uppercase,
     password_require_number, password_require_symbol, magic_link_enabled,
     magic_link_ttl_minutes, passkey_enabled, otp_email_enabled, otp_sms_enabled,
     self_registration_enabled, remember_device_enabled, updated_at)
VALUES (@tenant_id, @password_enabled, @password_min_length, @password_require_uppercase,
        @password_require_number, @password_require_symbol, @magic_link_enabled,
        @magic_link_ttl_minutes, @passkey_enabled, @otp_email_enabled, @otp_sms_enabled,
        @self_registration_enabled, @remember_device_enabled, NOW())
ON CONFLICT (tenant_id) DO UPDATE SET
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
    updated_at                = NOW()
RETURNING *;
