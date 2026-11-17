-- 0238_audit_purge_checkpoints — an organisation's audit events older than its
-- plan keeps them are deleted, and its chain verifies from where they were.
--
-- Plans promise how many days of audit history they keep (7, 30, 90 or
-- unlimited). A scheduled job deletes an organisation's older events, oldest
-- first, in batches. Each row here is where that chain now starts: the last
-- event deleted from it, whose row_hash the first event kept links to.
-- Verification starts there instead of at the chain's seed, and a scheduled
-- verification whose own checkpoint was deleted goes on from it. It is written
-- in the transaction that deletes the events.
CREATE TABLE platform.audit_purge_checkpoints (
    tenant_id        UUID PRIMARY KEY REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    event_id         UUID NOT NULL,
    event_created_at TIMESTAMPTZ NOT NULL,
    row_hash         CHAR(64) NOT NULL,
    events_purged    BIGINT NOT NULL DEFAULT 0,
    purged_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE platform.audit_purge_checkpoints ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON platform.audit_purge_checkpoints
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
