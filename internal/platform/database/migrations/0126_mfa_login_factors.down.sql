ALTER TABLE auth.mfa_login_challenges
    DROP COLUMN IF EXISTS codes_sent,
    DROP COLUMN IF EXISTS push_challenge_id,
    DROP COLUMN IF EXISTS passkey_session_id;
