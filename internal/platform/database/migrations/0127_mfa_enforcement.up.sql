-- 0127_mfa_enforcement — an organisation's MFA requirement is enforced at
-- password sign-in, with an optional grace period.
--
-- mfa_grace_days: how long after the organisation turns the requirement on
-- the accounts it already had may still sign in without a second factor
-- (prompted to set one up each time). 0 = no grace period.
-- mfa_enforced_since: when the requirement was last turned on; NULL while it
-- is optional. Organisations that already require MFA are enforced from now.
--
-- enrollment: the sign-in challenge is met by setting up an authenticator
-- app, because the account must have a second factor and holds none.
-- enrollment_started: an authenticator app has been started for it; only
-- then can a code confirm it.
ALTER TABLE tenant.security_policies
    ADD COLUMN IF NOT EXISTS mfa_grace_days INT NOT NULL DEFAULT 0
        CHECK (mfa_grace_days BETWEEN 0 AND 90),
    ADD COLUMN IF NOT EXISTS mfa_enforced_since TIMESTAMPTZ;
UPDATE tenant.security_policies
SET mfa_enforced_since = NOW()
WHERE mfa_enforcement <> 'optional' AND mfa_enforced_since IS NULL;

ALTER TABLE auth.mfa_login_challenges
    ADD COLUMN IF NOT EXISTS enrollment BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS enrollment_started BOOLEAN NOT NULL DEFAULT FALSE;
