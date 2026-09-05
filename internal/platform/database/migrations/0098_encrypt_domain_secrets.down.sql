DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM auth.mfa_totp WHERE secret_ct IS NOT NULL)
        OR EXISTS (SELECT 1 FROM tenant.webhook_subscriptions WHERE secret_ct IS NOT NULL)
        OR EXISTS (SELECT 1 FROM tenant.social_providers WHERE client_secret_ct IS NOT NULL)
        OR EXISTS (SELECT 1 FROM tenant.ldap_connections WHERE bind_password_ct IS NOT NULL)
        OR EXISTS (SELECT 1 FROM tenant.log_sinks WHERE token_ct IS NOT NULL)
        OR EXISTS (SELECT 1 FROM tenant.auth_hooks WHERE secret_ct IS NOT NULL)
        OR EXISTS (SELECT 1 FROM tenant.token_vault_providers WHERE client_secret_ct IS NOT NULL)
        OR EXISTS (SELECT 1 FROM auth.mfa_push_devices
                   WHERE push_token_ct IS NOT NULL OR push_token IS NULL OR device_token IS NULL)
    THEN
        RAISE EXCEPTION 'cannot roll back 0098: encrypted-only domain secrets exist'
            USING HINT = 'Restore a pre-0098 backup or deploy a controlled decrypt-and-downgrade migration.';
    END IF;
END $$;

DROP INDEX IF EXISTS auth.mfa_push_devices_user_token_hash;

ALTER TABLE auth.mfa_push_devices
    DROP COLUMN IF EXISTS encryption_version,
    DROP COLUMN IF EXISTS device_token_hash,
    DROP COLUMN IF EXISTS push_token_hash,
    DROP COLUMN IF EXISTS push_token_nonce,
    DROP COLUMN IF EXISTS push_token_ct;

ALTER TABLE auth.mfa_push_devices
    ALTER COLUMN push_token SET NOT NULL,
    ALTER COLUMN device_token SET NOT NULL;

ALTER TABLE tenant.token_vault_providers
    DROP COLUMN IF EXISTS encryption_version,
    DROP COLUMN IF EXISTS client_secret_nonce,
    DROP COLUMN IF EXISTS client_secret_ct;

ALTER TABLE tenant.auth_hooks
    DROP COLUMN IF EXISTS encryption_version,
    DROP COLUMN IF EXISTS secret_nonce,
    DROP COLUMN IF EXISTS secret_ct;

ALTER TABLE tenant.log_sinks
    DROP COLUMN IF EXISTS encryption_version,
    DROP COLUMN IF EXISTS token_nonce,
    DROP COLUMN IF EXISTS token_ct;

ALTER TABLE tenant.ldap_connections
    DROP COLUMN IF EXISTS encryption_version,
    DROP COLUMN IF EXISTS bind_password_nonce,
    DROP COLUMN IF EXISTS bind_password_ct;

ALTER TABLE tenant.social_providers
    DROP COLUMN IF EXISTS encryption_version,
    DROP COLUMN IF EXISTS client_secret_nonce,
    DROP COLUMN IF EXISTS client_secret_ct;

ALTER TABLE tenant.webhook_subscriptions
    DROP COLUMN IF EXISTS encryption_version,
    DROP COLUMN IF EXISTS secret_nonce,
    DROP COLUMN IF EXISTS secret_ct;

ALTER TABLE auth.mfa_totp
    DROP COLUMN IF EXISTS encryption_version,
    DROP COLUMN IF EXISTS secret_nonce,
    DROP COLUMN IF EXISTS secret_ct;

ALTER TABLE tenant.token_vault_grants
    DROP COLUMN IF EXISTS encryption_version;

ALTER TABLE tenant.secrets
    DROP COLUMN IF EXISTS encryption_version;
