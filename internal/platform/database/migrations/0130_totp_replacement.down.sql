ALTER TABLE auth.mfa_totp
    DROP CONSTRAINT IF EXISTS mfa_totp_pending_complete,
    DROP COLUMN IF EXISTS pending_started_at,
    DROP COLUMN IF EXISTS pending_secret_nonce,
    DROP COLUMN IF EXISTS pending_secret_ct;
