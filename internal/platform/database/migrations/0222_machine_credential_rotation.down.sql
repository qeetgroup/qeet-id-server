ALTER TABLE auth.agents
    DROP COLUMN IF EXISTS previous_secret_expires_at,
    DROP COLUMN IF EXISTS previous_secret_hash,
    DROP COLUMN IF EXISTS last_used_at;
ALTER TABLE auth.service_principals
    DROP COLUMN IF EXISTS previous_secret_expires_at,
    DROP COLUMN IF EXISTS previous_secret_hash,
    DROP COLUMN IF EXISTS last_used_at;
ALTER TABLE auth.api_keys
    DROP COLUMN IF EXISTS rotated_from,
    DROP COLUMN IF EXISTS created_by;
