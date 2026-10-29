-- 0215_audit_search_index — the full-text index over the rebuilt search column.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_search_vector ON audit.events USING GIN (search_vector);
