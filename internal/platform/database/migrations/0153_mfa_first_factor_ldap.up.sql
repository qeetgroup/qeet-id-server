-- 0153_mfa_first_factor_ldap — a directory (LDAP) sign-in is challenged for a
-- second factor like a password one, so a challenge's first factor may be
-- 'ldap' too: the session it completes is an "ldap_mfa" sign-in.
ALTER TABLE auth.mfa_login_challenges DROP CONSTRAINT IF EXISTS mfa_login_challenges_first_factor_check;
ALTER TABLE auth.mfa_login_challenges
    ADD CONSTRAINT mfa_login_challenges_first_factor_check
        CHECK (first_factor IN ('password', 'magic_link', 'social', 'ldap'));
