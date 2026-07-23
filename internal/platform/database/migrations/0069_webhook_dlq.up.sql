-- 0069_webhook_dlq — dead_at marks a webhook delivery that exhausted its retry budget (see maxDeliveryAttempts), so a permanently-failing endpoint stops retrying forever
ALTER TABLE tenant.webhook_deliveries ADD COLUMN IF NOT EXISTS dead_at TIMESTAMPTZ;
