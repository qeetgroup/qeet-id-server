-- 0097_gdpr_tenant_ownership ensures queued GDPR work cannot pair one tenant
-- with a user owned by another tenant. Existing mismatches are preserved as
-- quarantined/failed evidence and are never executed.

ALTER TABLE "user".users
    ADD CONSTRAINT users_id_tenant_id_key UNIQUE (id, tenant_id);

ALTER TABLE "user".purge_requests
    DROP CONSTRAINT purge_requests_status_check;
ALTER TABLE "user".purge_requests
    ADD COLUMN quarantined_at TIMESTAMPTZ,
    ADD COLUMN quarantine_reason TEXT,
    ADD CONSTRAINT purge_requests_status_check
        CHECK (status IN ('pending', 'completed', 'cancelled', 'quarantined'));

UPDATE "user".purge_requests pr
SET status = 'quarantined',
    quarantined_at = NOW(),
    quarantine_reason = 'tenant ownership mismatch found during migration 0097'
WHERE NOT EXISTS (
    SELECT 1
    FROM "user".users u
    WHERE u.id = pr.user_id AND u.tenant_id = pr.tenant_id
);

ALTER TABLE "user".purge_requests
    ADD CONSTRAINT purge_requests_user_tenant_fkey
    FOREIGN KEY (user_id, tenant_id)
    REFERENCES "user".users (id, tenant_id)
    ON DELETE CASCADE
    NOT VALID;
ALTER TABLE "user".purge_requests
    VALIDATE CONSTRAINT purge_requests_user_tenant_fkey;

UPDATE "user".export_requests er
SET status = 'failed',
    error = 'tenant ownership mismatch found during migration 0097',
    completed_at = NOW()
WHERE NOT EXISTS (
    SELECT 1
    FROM "user".users u
    WHERE u.id = er.user_id AND u.tenant_id = er.tenant_id
);

ALTER TABLE "user".export_requests
    ADD CONSTRAINT export_requests_user_tenant_fkey
    FOREIGN KEY (user_id, tenant_id)
    REFERENCES "user".users (id, tenant_id)
    ON DELETE CASCADE
    NOT VALID;
ALTER TABLE "user".export_requests
    VALIDATE CONSTRAINT export_requests_user_tenant_fkey;
