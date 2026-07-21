DROP TABLE IF EXISTS auth.login_context_history;
ALTER TABLE auth.risk_settings
    DROP COLUMN IF EXISTS impossible_travel_enabled,
    DROP COLUMN IF EXISTS min_travel_hours,
    DROP COLUMN IF EXISTS device_reputation_enabled;
