-- 0200_audit_platform_chain_index — each platform chain's tip and rows are
-- found by its shard, the platform rows alone.
CREATE INDEX CONCURRENTLY idx_audit_platform_chain ON audit.events (chain_shard, created_at DESC, id DESC)
    WHERE tenant_id IS NULL AND row_hash IS NOT NULL;
