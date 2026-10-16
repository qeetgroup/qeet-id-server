ALTER TABLE auth.security_events
    DROP COLUMN IF EXISTS metadata;
ALTER TABLE tenant.auth_policy
    DROP COLUMN IF EXISTS lockout_duration_minutes,
    DROP COLUMN IF EXISTS lockout_window_minutes,
    DROP COLUMN IF EXISTS lockout_threshold;
DROP TABLE IF EXISTS auth.login_source_throttles;
DROP TABLE IF EXISTS auth.login_source_failures;
DROP TABLE IF EXISTS auth.login_attempts_by_network;
