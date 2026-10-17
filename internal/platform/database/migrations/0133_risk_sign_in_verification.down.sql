ALTER TABLE auth.mfa_login_challenges
    DROP COLUMN IF EXISTS email_code_sent_at,
    DROP COLUMN IF EXISTS email_code_expires_at,
    DROP COLUMN IF EXISTS email_code_hash,
    DROP COLUMN IF EXISTS risk_email;
