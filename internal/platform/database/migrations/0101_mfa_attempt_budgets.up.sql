ALTER TABLE auth.mfa_login_challenges
    ADD COLUMN failed_attempts SMALLINT NOT NULL DEFAULT 0
        CHECK (failed_attempts >= 0 AND failed_attempts <= 5);

CREATE TABLE auth.mfa_attempt_budgets (
    user_id           UUID        NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    purpose           TEXT        NOT NULL CHECK (length(purpose) BETWEEN 1 AND 128),
    failed_attempts   SMALLINT    NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0 AND failed_attempts <= 5),
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until      TIMESTAMPTZ,
    PRIMARY KEY (user_id, purpose)
);

CREATE INDEX mfa_attempt_budgets_locked
    ON auth.mfa_attempt_budgets (locked_until)
    WHERE locked_until IS NOT NULL;
