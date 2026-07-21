-- Per-account brute-force throttling. Tracks consecutive failed logins keyed by
-- (lowercased) email and locks the account for a cooldown once a threshold is
-- crossed. DB-backed so the limit holds across all API replicas — unlike the
-- in-memory per-IP rate limiter.
CREATE TABLE auth.login_attempts (
    email           TEXT PRIMARY KEY,
    failed_count    INT         NOT NULL DEFAULT 0,
    first_failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_failed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until    TIMESTAMPTZ
);

-- Supports a periodic cleanup job that purges stale rows.
CREATE INDEX login_attempts_last_failed_at_idx ON auth.login_attempts (last_failed_at);
