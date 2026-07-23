-- 0023_audit_hashchain — tamper-evident hash chain on audit.events.
-- row_hash = sha256(canonical_json(row || prev_hash)); prev_hash chains per-tenant (NULL tenant_id = the "platform" chain).
-- Pre-migration rows are NULL/NULL; the app enforces non-NULL thereafter and verifies from the first row whose prev_hash is the all-zero seed.

ALTER TABLE audit.events
    ADD COLUMN prev_hash CHAR(64),
    ADD COLUMN row_hash  CHAR(64);

ALTER TABLE audit.events
    ADD CONSTRAINT audit_events_hash_both_or_neither
    CHECK ((prev_hash IS NULL) = (row_hash IS NULL));

-- Hot path for "fetch the chain tip for a tenant".
CREATE INDEX idx_audit_chain_tip
    ON audit.events (tenant_id, created_at DESC, id DESC)
    WHERE row_hash IS NOT NULL;
