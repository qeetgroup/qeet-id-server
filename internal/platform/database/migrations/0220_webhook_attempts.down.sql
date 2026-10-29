DROP TABLE IF EXISTS tenant.webhook_delivery_attempts;
ALTER TABLE tenant.webhook_subscriptions DROP COLUMN IF EXISTS disabled_by;
