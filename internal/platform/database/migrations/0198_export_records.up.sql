-- 0198_export_records — a data-export request outlives the account it is about.
--
-- Deleting an account for good took its export requests with it, so the record
-- that the person's data was handed over went too. The request now keeps the
-- account's ID in subject_id and forgets the account; its payload is deleted
-- as before. The organisation's deletion still removes its requests.
ALTER TABLE "user".export_requests ADD COLUMN subject_id UUID;
UPDATE "user".export_requests SET subject_id = user_id;
ALTER TABLE "user".export_requests
    ALTER COLUMN subject_id SET NOT NULL,
    ALTER COLUMN user_id DROP NOT NULL,
    ADD CONSTRAINT export_requests_subject_check CHECK (user_id IS NULL OR user_id = subject_id),
    DROP CONSTRAINT export_requests_user_id_fkey,
    ADD CONSTRAINT export_requests_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES "user".users (id) ON DELETE SET NULL,
    DROP CONSTRAINT export_requests_user_tenant_fkey,
    ADD CONSTRAINT export_requests_user_tenant_fkey FOREIGN KEY (user_id, tenant_id)
        REFERENCES "user".users (id, tenant_id) ON DELETE SET NULL (user_id),
    DROP CONSTRAINT export_requests_tenant_id_fkey,
    ADD CONSTRAINT export_requests_tenant_id_fkey FOREIGN KEY (tenant_id)
        REFERENCES tenant.tenants (id) ON DELETE CASCADE;
