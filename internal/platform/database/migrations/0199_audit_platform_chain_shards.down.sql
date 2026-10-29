ALTER TABLE platform.audit_chain_checkpoints DROP CONSTRAINT audit_chain_checkpoints_tenant_id_chain_shard_key;
DELETE FROM platform.audit_chain_checkpoints WHERE chain_shard <> 0;
ALTER TABLE platform.audit_chain_checkpoints
    ADD CONSTRAINT audit_chain_checkpoints_tenant_id_key UNIQUE NULLS NOT DISTINCT (tenant_id),
    DROP COLUMN chain_shard;
ALTER TABLE audit.events DROP COLUMN chain_shard;
