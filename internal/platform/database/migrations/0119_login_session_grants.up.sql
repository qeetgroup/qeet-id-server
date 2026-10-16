-- 0119_login_session_grants — know which hosted-login session started an
-- application's sign-in, so signing out of that session can end it.
--
-- auth.login_sessions (migration 0042) is keyed by the cookie's hash and had
-- no id another table could point at. Authorization codes minted through a
-- hosted-login session, and the refresh grants redeemed from them, now record
-- that session's id; a renewal carries it forward to the next token. Signing
-- out of the session spends its unredeemed codes and revokes its grants.
--
-- No foreign key: signing out deletes the session row, while the grants it
-- started stay on record as revoked, still naming it. NULL means the code or
-- grant did not come from a hosted-login session (device and back-channel
-- flows, and everything issued before this migration).
ALTER TABLE auth.login_sessions
    ADD COLUMN IF NOT EXISTS id UUID NOT NULL DEFAULT gen_random_uuid();
CREATE UNIQUE INDEX IF NOT EXISTS login_sessions_id_key ON auth.login_sessions (id);

ALTER TABLE auth.oidc_authorization_codes ADD COLUMN IF NOT EXISTS login_session_id UUID;
ALTER TABLE auth.oidc_refresh_tokens      ADD COLUMN IF NOT EXISTS login_session_id UUID;

-- Partial: sign-out only looks for codes not yet redeemed and grants not yet
-- revoked, and neither ever comes back.
CREATE INDEX IF NOT EXISTS idx_oidc_codes_login_session_unused
    ON auth.oidc_authorization_codes (login_session_id)
    WHERE login_session_id IS NOT NULL AND used_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_login_session_unrevoked
    ON auth.oidc_refresh_tokens (login_session_id)
    WHERE login_session_id IS NOT NULL AND revoked_at IS NULL;
