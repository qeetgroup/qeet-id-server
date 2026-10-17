-- 0133_risk_sign_in_verification — a risky sign-in by someone with no second
-- factor proves it with a code sent to their verified email.
--
-- auth.mfa_login_challenges.risk_email: the challenge is met by a code sent to
-- the account's verified email address, because the sign-in was assessed as
-- risky and the person holds no second factor to ask for. email_code_hash is
-- the latest such code (SHA-256), valid until email_code_expires_at;
-- email_code_sent_at paces resending.
ALTER TABLE auth.mfa_login_challenges
    ADD COLUMN IF NOT EXISTS risk_email BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS email_code_hash TEXT,
    ADD COLUMN IF NOT EXISTS email_code_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS email_code_sent_at TIMESTAMPTZ;
