DROP TABLE IF EXISTS audit.anomaly_settings;
DROP TABLE IF EXISTS audit.anomalies;
DROP TABLE IF EXISTS audit.actor_baselines;
DROP INDEX IF EXISTS audit.idx_audit_events_unscored;
ALTER TABLE audit.events DROP COLUMN IF EXISTS scored_at;
