ALTER TABLE auth.mfa_totp
    DROP COLUMN IF EXISTS last_used_step;
