-- 0150_mfa_first_factor_social — a social sign-in (Google, Microsoft, GitHub,
-- Apple, or an organisation's own provider) is challenged for a second factor
-- like a password or magic-link one (QTID-801), so a challenge's first factor
-- may be 'social' too: the session it completes is a "social_mfa" sign-in.
ALTER TABLE auth.mfa_login_challenges DROP CONSTRAINT IF EXISTS mfa_login_challenges_first_factor_check;
ALTER TABLE auth.mfa_login_challenges
    ADD CONSTRAINT mfa_login_challenges_first_factor_check
        CHECK (first_factor IN ('password', 'magic_link', 'social'));
