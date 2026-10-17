ALTER TABLE auth.mfa_login_challenges
    DROP COLUMN IF EXISTS enrollment_started,
    DROP COLUMN IF EXISTS enrollment;
ALTER TABLE tenant.security_policies
    DROP COLUMN IF EXISTS mfa_enforced_since,
    DROP COLUMN IF EXISTS mfa_grace_days;
