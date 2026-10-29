-- 0176_audit_chain_checkpoints — the scheduled audit verification goes on
-- from where it left each chain.
--
-- Every six hours it walked every chain from its first row, so each run took
-- longer as the log grew. It now keeps each chain's last verified row here and
-- walks only the rows after it, checking that row again first. Once a week, and
-- for a chain with no row here, it walks from the first row, so a changed old
-- row is still found. A chain found broken keeps its row, marked broken_at:
-- every run then checks it again and walks the chain from the start, until an
-- operator who has looked into it deletes the row.
CREATE TABLE platform.audit_chain_checkpoints (
    tenant_id        UUID, -- the organisation's chain; NULL for the platform chain
    event_id         UUID NOT NULL UNIQUE,
    event_created_at TIMESTAMPTZ NOT NULL,
    row_hash         CHAR(64) NOT NULL,
    verified_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    broken_at        TIMESTAMPTZ,
    UNIQUE NULLS NOT DISTINCT (tenant_id)
);

ALTER TABLE platform.audit_chain_checkpoints ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON platform.audit_chain_checkpoints
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
