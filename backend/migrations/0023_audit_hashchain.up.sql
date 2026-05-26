-- Tamper-evident hash chain on audit.events. Each row's row_hash is
-- sha256(canonical_json(row || prev_hash)). prev_hash points at the previous
-- row's row_hash, scoped per-tenant (a separate chain per tenant_id, with
-- NULL tenant_id forming the "platform" chain).
--
-- Pre-migration rows have NULL prev_hash and row_hash. The application
-- enforces non-NULL for all subsequent inserts; verification starts at the
-- first non-NULL row whose prev_hash equals the all-zero seed.

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
