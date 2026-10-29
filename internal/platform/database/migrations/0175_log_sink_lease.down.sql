ALTER TABLE tenant.log_sinks
    DROP COLUMN leased_until,
    DROP COLUMN failures,
    DROP COLUMN next_attempt_at;
