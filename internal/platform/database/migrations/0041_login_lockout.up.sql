-- 0041_login_lockout — per-account brute-force throttle keyed by lowercased email.
-- DB-backed so the limit holds across all API replicas (unlike the in-memory per-IP limiter).
CREATE TABLE auth.login_attempts (
    email           TEXT PRIMARY KEY,
    failed_count    INT         NOT NULL DEFAULT 0,
    first_failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_failed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until    TIMESTAMPTZ
);

-- Supports a periodic cleanup job that purges stale rows.
CREATE INDEX login_attempts_last_failed_at_idx ON auth.login_attempts (last_failed_at);
