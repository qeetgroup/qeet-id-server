DROP INDEX IF EXISTS audit.idx_audit_search_vector;
ALTER TABLE audit.events DROP COLUMN IF EXISTS search_vector;
