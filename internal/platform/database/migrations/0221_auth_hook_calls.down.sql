ALTER TABLE tenant.auth_hooks
    DROP COLUMN IF EXISTS deny_count,
    DROP COLUMN IF EXISTS skip_count,
    DROP COLUMN IF EXISTS call_count,
    DROP COLUMN IF EXISTS last_status_code,
    DROP COLUMN IF EXISTS last_outcome,
    DROP COLUMN IF EXISTS last_called_at;
