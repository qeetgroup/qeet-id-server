-- Webhook retry currently has no give-up state — a permanently-failing
-- endpoint retries forever at the 1h backoff ceiling. dead_at marks a
-- delivery that exhausted its retry budget (see maxDeliveryAttempts), mirroring
-- the delivered_at/timestamp-presence-as-state pattern already used here.
ALTER TABLE tenant.webhook_deliveries ADD COLUMN IF NOT EXISTS dead_at TIMESTAMPTZ;
