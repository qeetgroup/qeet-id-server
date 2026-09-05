ALTER TABLE "user".export_requests
    DROP CONSTRAINT IF EXISTS export_requests_user_tenant_fkey;

ALTER TABLE "user".purge_requests
    DROP CONSTRAINT IF EXISTS purge_requests_user_tenant_fkey;

UPDATE "user".purge_requests
SET status = 'cancelled'
WHERE status = 'quarantined';

ALTER TABLE "user".purge_requests
    DROP CONSTRAINT purge_requests_status_check;
ALTER TABLE "user".purge_requests
    ADD CONSTRAINT purge_requests_status_check
        CHECK (status IN ('pending', 'completed', 'cancelled'));
ALTER TABLE "user".purge_requests
    DROP COLUMN IF EXISTS quarantined_at,
    DROP COLUMN IF EXISTS quarantine_reason;

ALTER TABLE "user".users
    DROP CONSTRAINT IF EXISTS users_id_tenant_id_key;
