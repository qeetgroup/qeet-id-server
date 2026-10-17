-- 0128_mfa_first_factor — a sign-in challenge records how the first factor
-- was proven ('password' or 'magic_link'), so the session it completes and
-- the audit trail say which sign-in met a second factor.
ALTER TABLE auth.mfa_login_challenges
    ADD COLUMN IF NOT EXISTS first_factor TEXT NOT NULL DEFAULT 'password'
        CHECK (first_factor IN ('password', 'magic_link'));
