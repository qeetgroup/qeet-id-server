ALTER TABLE platform.audit_purge_checkpoints
    DROP COLUMN IF EXISTS mac,
    DROP COLUMN IF EXISTS key_id;

ALTER TABLE platform.audit_chain_checkpoints
    DROP COLUMN IF EXISTS mac,
    DROP COLUMN IF EXISTS key_id;
