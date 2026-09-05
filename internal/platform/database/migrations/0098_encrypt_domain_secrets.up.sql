-- 0098_encrypt_domain_secrets expands every legacy plaintext secret table with
-- versioned ciphertext storage. Application readers retain legacy fallback so
-- data can be migrated online before the plaintext columns are removed later.

ALTER TABLE tenant.secrets
    ADD COLUMN encryption_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE tenant.secrets
    ALTER COLUMN encryption_version SET DEFAULT 1;

ALTER TABLE tenant.token_vault_grants
    ADD COLUMN encryption_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE tenant.token_vault_grants
    ALTER COLUMN encryption_version SET DEFAULT 1;

ALTER TABLE auth.mfa_totp
    ADD COLUMN secret_ct BYTEA,
    ADD COLUMN secret_nonce BYTEA,
    ADD COLUMN encryption_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE tenant.webhook_subscriptions
    ADD COLUMN secret_ct BYTEA,
    ADD COLUMN secret_nonce BYTEA,
    ADD COLUMN encryption_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE tenant.social_providers
    ADD COLUMN client_secret_ct BYTEA,
    ADD COLUMN client_secret_nonce BYTEA,
    ADD COLUMN encryption_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE tenant.ldap_connections
    ADD COLUMN bind_password_ct BYTEA,
    ADD COLUMN bind_password_nonce BYTEA,
    ADD COLUMN encryption_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE tenant.log_sinks
    ADD COLUMN token_ct BYTEA,
    ADD COLUMN token_nonce BYTEA,
    ADD COLUMN encryption_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE tenant.auth_hooks
    ADD COLUMN secret_ct BYTEA,
    ADD COLUMN secret_nonce BYTEA,
    ADD COLUMN encryption_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE tenant.token_vault_providers
    ADD COLUMN client_secret_ct BYTEA,
    ADD COLUMN client_secret_nonce BYTEA,
    ADD COLUMN encryption_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE auth.mfa_push_devices
    ALTER COLUMN push_token DROP NOT NULL,
    ALTER COLUMN device_token DROP NOT NULL,
    ADD COLUMN push_token_ct BYTEA,
    ADD COLUMN push_token_nonce BYTEA,
    ADD COLUMN push_token_hash TEXT,
    ADD COLUMN device_token_hash TEXT,
    ADD COLUMN encryption_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE auth.mfa_totp
    ADD CONSTRAINT mfa_totp_secret_storage_valid CHECK (
        (encryption_version = 0 AND secret <> '' AND secret_ct IS NULL AND secret_nonce IS NULL)
        OR
        (encryption_version = 1 AND secret = '' AND secret_ct IS NOT NULL AND secret_nonce IS NOT NULL)
    );

ALTER TABLE tenant.webhook_subscriptions
    ADD CONSTRAINT webhook_secret_storage_valid CHECK (
        (encryption_version = 0 AND secret <> '' AND secret_ct IS NULL AND secret_nonce IS NULL)
        OR
        (encryption_version = 1 AND secret = '' AND secret_ct IS NOT NULL AND secret_nonce IS NOT NULL)
    );

ALTER TABLE tenant.social_providers
    ADD CONSTRAINT social_provider_secret_storage_valid CHECK (
        (encryption_version = 0 AND client_secret <> '' AND client_secret_ct IS NULL AND client_secret_nonce IS NULL)
        OR
        (encryption_version = 1 AND client_secret = '' AND client_secret_ct IS NOT NULL AND client_secret_nonce IS NOT NULL)
    );

ALTER TABLE tenant.ldap_connections
    ADD CONSTRAINT ldap_bind_secret_storage_valid CHECK (
        (encryption_version = 0 AND bind_password <> '' AND bind_password_ct IS NULL AND bind_password_nonce IS NULL)
        OR
        (encryption_version = 1 AND bind_password = '' AND bind_password_ct IS NOT NULL AND bind_password_nonce IS NOT NULL)
    );

ALTER TABLE tenant.log_sinks
    ADD CONSTRAINT log_sink_token_storage_valid CHECK (
        (encryption_version = 0 AND token_ct IS NULL AND token_nonce IS NULL)
        OR
        (encryption_version = 1 AND token = '' AND token_ct IS NOT NULL AND token_nonce IS NOT NULL)
    );

ALTER TABLE tenant.auth_hooks
    ADD CONSTRAINT auth_hook_secret_storage_valid CHECK (
        (encryption_version = 0 AND secret <> '' AND secret_ct IS NULL AND secret_nonce IS NULL)
        OR
        (encryption_version = 1 AND secret = '' AND secret_ct IS NOT NULL AND secret_nonce IS NOT NULL)
    );

ALTER TABLE tenant.token_vault_providers
    ADD CONSTRAINT token_vault_provider_secret_storage_valid CHECK (
        (encryption_version = 0 AND client_secret <> '' AND client_secret_ct IS NULL AND client_secret_nonce IS NULL)
        OR
        (encryption_version = 1 AND client_secret = '' AND client_secret_ct IS NOT NULL AND client_secret_nonce IS NOT NULL)
    );

ALTER TABLE auth.mfa_push_devices
    ADD CONSTRAINT mfa_push_secret_storage_valid CHECK (
        (encryption_version = 0 AND push_token IS NOT NULL AND device_token IS NOT NULL
            AND push_token_ct IS NULL AND push_token_nonce IS NULL
            AND push_token_hash IS NULL AND device_token_hash IS NULL)
        OR
        (encryption_version = 1 AND push_token IS NULL AND device_token IS NULL
            AND push_token_ct IS NOT NULL AND push_token_nonce IS NOT NULL
            AND push_token_hash IS NOT NULL AND device_token_hash IS NOT NULL)
    );

CREATE UNIQUE INDEX mfa_push_devices_user_token_hash
    ON auth.mfa_push_devices (user_id, push_token_hash)
    WHERE push_token_hash IS NOT NULL;
