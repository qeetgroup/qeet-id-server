ALTER TABLE tenant.secrets
    DROP COLUMN rotation_interval_days,
    DROP COLUMN value_changed_at,
    DROP COLUMN last_revealed_credential,
    DROP COLUMN last_revealed_by,
    DROP COLUMN last_revealed_at;
