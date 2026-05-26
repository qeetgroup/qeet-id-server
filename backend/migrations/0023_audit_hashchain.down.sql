DROP INDEX IF EXISTS audit.idx_audit_chain_tip;
ALTER TABLE audit.events DROP CONSTRAINT IF EXISTS audit_events_hash_both_or_neither;
ALTER TABLE audit.events DROP COLUMN IF EXISTS row_hash;
ALTER TABLE audit.events DROP COLUMN IF EXISTS prev_hash;
