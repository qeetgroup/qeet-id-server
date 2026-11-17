ALTER TABLE tenant.auth_hooks
    DROP COLUMN IF EXISTS previous_secret_ct,
    DROP COLUMN IF EXISTS previous_secret_nonce,
    DROP COLUMN IF EXISTS previous_secret_expires_at;
