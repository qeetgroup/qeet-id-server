-- 0130_totp_replacement — setting up a new authenticator app no longer
-- switches off the one that works.
--
-- While an account holds a confirmed authenticator app, a new setup is kept
-- apart in pending_secret_ct / pending_secret_nonce (sealed like secret_ct)
-- until a code from the new app confirms it; until then the current app keeps
-- signing in and stepping up. A pending setup not confirmed within 30 minutes
-- of pending_started_at is ignored and the account is unchanged.
ALTER TABLE auth.mfa_totp
    ADD COLUMN IF NOT EXISTS pending_secret_ct BYTEA,
    ADD COLUMN IF NOT EXISTS pending_secret_nonce BYTEA,
    ADD COLUMN IF NOT EXISTS pending_started_at TIMESTAMPTZ,
    ADD CONSTRAINT mfa_totp_pending_complete CHECK (
        (pending_secret_ct IS NULL AND pending_secret_nonce IS NULL AND pending_started_at IS NULL)
        OR (pending_secret_ct IS NOT NULL AND pending_secret_nonce IS NOT NULL AND pending_started_at IS NOT NULL));
