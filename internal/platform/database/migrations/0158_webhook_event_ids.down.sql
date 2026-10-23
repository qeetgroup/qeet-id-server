ALTER TABLE tenant.webhook_deliveries DROP CONSTRAINT webhook_deliveries_subscription_event_key;
ALTER TABLE tenant.webhook_deliveries DROP COLUMN event_id;
