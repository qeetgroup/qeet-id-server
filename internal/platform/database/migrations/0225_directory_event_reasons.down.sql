ALTER TABLE tenant.directory_events
    DROP COLUMN IF EXISTS user_id,
    DROP COLUMN IF EXISTS subject,
    DROP COLUMN IF EXISTS params,
    DROP COLUMN IF EXISTS reason;
