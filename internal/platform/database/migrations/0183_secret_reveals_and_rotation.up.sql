-- 0183_secret_reveals_and_rotation — who last revealed a secret, and when it
-- is due to be rotated.
--
-- A reveal records the time and the person (or, for a machine credential, the
-- credential) on the secret, so the list shows it without reading the audit
-- log. value_changed_at is when the value was last set; a scope-only change
-- moves updated_at but not it. An optional rotation interval, in days, makes
-- the secret due that long after the value last changed. Secrets from before
-- this take their last update as the last change of value.
ALTER TABLE tenant.secrets
    ADD COLUMN last_revealed_at TIMESTAMPTZ,
    ADD COLUMN last_revealed_by UUID,
    ADD COLUMN last_revealed_credential TEXT,
    ADD COLUMN value_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN rotation_interval_days INTEGER
        CHECK (rotation_interval_days BETWEEN 1 AND 3650);

UPDATE tenant.secrets SET value_changed_at = updated_at;
