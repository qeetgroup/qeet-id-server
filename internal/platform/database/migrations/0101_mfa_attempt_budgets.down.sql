DROP TABLE IF EXISTS auth.mfa_attempt_budgets;

ALTER TABLE auth.mfa_login_challenges
    DROP COLUMN IF EXISTS failed_attempts;
