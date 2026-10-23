-- 0158_webhook_event_ids — each webhook delivery names the event it carries,
-- and a subscription gets one delivery per event.
--
-- Events reach webhooks from the outbox, which can hand an event over again
-- after a failure part-way; the key makes that a no-op instead of a second
-- delivery. The id is also the event id receivers deduplicate on. Deliveries
-- queued before this get an id of their own.
ALTER TABLE tenant.webhook_deliveries ADD COLUMN event_id UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE tenant.webhook_deliveries ALTER COLUMN event_id DROP DEFAULT;
ALTER TABLE tenant.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_subscription_event_key UNIQUE (subscription_id, event_id);
