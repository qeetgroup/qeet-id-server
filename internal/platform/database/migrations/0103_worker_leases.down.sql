DROP INDEX IF EXISTS "user".export_request_lease_due;
DROP INDEX IF EXISTS "user".purge_request_lease_due;
DROP INDEX IF EXISTS tenant.webhook_delivery_lease_due;
DROP INDEX IF EXISTS platform.outbox_lease_due;

ALTER TABLE "user".export_requests
    DROP COLUMN IF EXISTS lease_until,
    DROP COLUMN IF EXISTS lease_owner;
ALTER TABLE "user".purge_requests
    DROP COLUMN IF EXISTS lease_until,
    DROP COLUMN IF EXISTS lease_owner;
ALTER TABLE tenant.webhook_deliveries
    DROP COLUMN IF EXISTS lease_until,
    DROP COLUMN IF EXISTS lease_owner;
ALTER TABLE platform.outbox
    DROP COLUMN IF EXISTS lease_until,
    DROP COLUMN IF EXISTS lease_owner;
