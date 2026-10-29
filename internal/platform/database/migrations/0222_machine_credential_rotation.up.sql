-- 0222_machine_credential_rotation — machine credentials rotate with an
-- overlap and say when they were last used: an API key records who created it
-- and the key it replaced; a machine identity and an agent keep their
-- previous secret until it expires, and their last use.
ALTER TABLE auth.api_keys
    ADD COLUMN IF NOT EXISTS created_by UUID,
    ADD COLUMN IF NOT EXISTS rotated_from UUID;

ALTER TABLE auth.service_principals
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS previous_secret_hash TEXT,
    ADD COLUMN IF NOT EXISTS previous_secret_expires_at TIMESTAMPTZ;

ALTER TABLE auth.agents
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS previous_secret_hash TEXT,
    ADD COLUMN IF NOT EXISTS previous_secret_expires_at TIMESTAMPTZ;
