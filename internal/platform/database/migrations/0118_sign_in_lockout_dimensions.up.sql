-- 0118_sign_in_lockout_dimensions — count failed sign-ins per account AND
-- source network, per source across accounts, and let a tenant set its own
-- lockout threshold, window and duration.
--
-- auth.login_attempts (migration 0041) counted failures per lowercased email
-- alone, so anyone who knew an address could lock its owner out. It stays, as
-- the looser per-account cap that still bounds an attack spread over many
-- networks. The lock a tenant configures is now held per account and source
-- network (an IPv4 address or an IPv6 /64), so failures from a network that
-- does not control the account cannot alone exhaust the owner's allowance.
CREATE TABLE IF NOT EXISTS auth.login_attempts_by_network (
    email           TEXT        NOT NULL,
    network         TEXT        NOT NULL,
    failed_count    INT         NOT NULL,
    first_failed_at TIMESTAMPTZ NOT NULL,
    last_failed_at  TIMESTAMPTZ NOT NULL,
    locked_until    TIMESTAMPTZ,
    PRIMARY KEY (email, network)
);
CREATE INDEX IF NOT EXISTS login_attempts_by_network_last_failed_at_idx
    ON auth.login_attempts_by_network (last_failed_at);

-- The accounts each source network failed to sign in to recently, so a
-- broad-and-shallow spraying run (a few guesses against many accounts) is
-- counted and throttled per source. Rows older than the window are removed
-- for a network each time it fails again.
CREATE TABLE IF NOT EXISTS auth.login_source_failures (
    network        TEXT        NOT NULL,
    email          TEXT        NOT NULL,
    last_failed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (network, email)
);

-- Source networks currently refused password sign-in for spraying.
CREATE TABLE IF NOT EXISTS auth.login_source_throttles (
    network           TEXT        PRIMARY KEY,
    throttled_at      TIMESTAMPTZ NOT NULL,
    throttled_until   TIMESTAMPTZ NOT NULL,
    distinct_accounts INT         NOT NULL
);

-- A tenant's lockout settings. NULL = the platform default (LOGIN_LOCKOUT_*);
-- the bounds a tenant may choose within are platform configuration, enforced
-- by the API, so the columns only refuse nonsense.
ALTER TABLE tenant.auth_policy
    ADD COLUMN IF NOT EXISTS lockout_threshold        INT CHECK (lockout_threshold > 0),
    ADD COLUMN IF NOT EXISTS lockout_window_minutes   INT CHECK (lockout_window_minutes > 0),
    ADD COLUMN IF NOT EXISTS lockout_duration_minutes INT CHECK (lockout_duration_minutes > 0);

-- Structured context for a security signal (for a lockout: the reason, the
-- account, the source network and which counter tripped).
ALTER TABLE auth.security_events
    ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
