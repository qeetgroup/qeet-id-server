-- 0242_audit_checkpoint_signatures — an audit checkpoint carries a MAC only the
-- server can make, so a chain rewritten together with its checkpoint is found.
--
-- Each event's row_hash is a plain SHA-256 that anyone able to write
-- audit.events can recompute. A scheduled verification's checkpoint, and a
-- purge's, now also stores mac: an HMAC-SHA256 of the chain, the row and its
-- row_hash under a key derived from the secrets data key key_id names. The
-- existing chain checkpoints are unsigned, so they are deleted: the next run
-- walks every chain from its first row and signs new ones. Purge checkpoints
-- arrive in the same release, so none is unsigned.
ALTER TABLE platform.audit_chain_checkpoints
    ADD COLUMN key_id TEXT,
    ADD COLUMN mac    BYTEA;

ALTER TABLE platform.audit_purge_checkpoints
    ADD COLUMN key_id TEXT,
    ADD COLUMN mac    BYTEA;

DELETE FROM platform.audit_chain_checkpoints;
