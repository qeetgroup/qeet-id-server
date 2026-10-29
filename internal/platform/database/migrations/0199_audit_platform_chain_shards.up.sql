-- 0199_audit_platform_chain_shards — events with no organisation (sign-up,
-- sign-in before an organisation is known) go on one of 16 platform chains.
--
-- Every such event joined one platform chain, and each write held its lock
-- until commit, so a burst of sign-ups queued on one lock however many
-- instances ran. Each platform event now names its chain, chain_shard 0..15,
-- each a whole hash chain with its own tip, lock and checkpoint. The rows
-- already there, and every organisation's, are shard 0, so the existing chains
-- verify unchanged. A constant default adds the column without rewriting the
-- table.
ALTER TABLE audit.events ADD COLUMN chain_shard SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE platform.audit_chain_checkpoints
    ADD COLUMN chain_shard SMALLINT NOT NULL DEFAULT 0,
    DROP CONSTRAINT audit_chain_checkpoints_tenant_id_key,
    ADD CONSTRAINT audit_chain_checkpoints_tenant_id_chain_shard_key UNIQUE NULLS NOT DISTINCT (tenant_id, chain_shard);
