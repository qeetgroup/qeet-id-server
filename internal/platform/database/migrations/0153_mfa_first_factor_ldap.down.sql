DELETE FROM auth.mfa_login_challenges WHERE first_factor = 'ldap';
ALTER TABLE auth.mfa_login_challenges DROP CONSTRAINT IF EXISTS mfa_login_challenges_first_factor_check;
ALTER TABLE auth.mfa_login_challenges
    ADD CONSTRAINT mfa_login_challenges_first_factor_check
        CHECK (first_factor IN ('password', 'magic_link', 'social'));
