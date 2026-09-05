ALTER TABLE platform.outbox
    ADD COLUMN lease_owner UUID,
    ADD COLUMN lease_until TIMESTAMPTZ;

ALTER TABLE tenant.webhook_deliveries
    ADD COLUMN lease_owner UUID,
    ADD COLUMN lease_until TIMESTAMPTZ;

ALTER TABLE "user".purge_requests
    ADD COLUMN lease_owner UUID,
    ADD COLUMN lease_until TIMESTAMPTZ;

ALTER TABLE "user".export_requests
    ADD COLUMN lease_owner UUID,
    ADD COLUMN lease_until TIMESTAMPTZ;

CREATE INDEX outbox_lease_due
    ON platform.outbox (lease_until, created_at)
    WHERE published_at IS NULL;
CREATE INDEX webhook_delivery_lease_due
    ON tenant.webhook_deliveries (lease_until, next_attempt_at)
    WHERE delivered_at IS NULL AND dead_at IS NULL;
CREATE INDEX purge_request_lease_due
    ON "user".purge_requests (lease_until, grace_until)
    WHERE status = 'pending';
CREATE INDEX export_request_lease_due
    ON "user".export_requests (lease_until, created_at)
    WHERE status = 'pending';
