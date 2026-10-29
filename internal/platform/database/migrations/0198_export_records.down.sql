DELETE FROM "user".export_requests WHERE user_id IS NULL;
ALTER TABLE "user".export_requests
    DROP CONSTRAINT export_requests_tenant_id_fkey,
    ADD CONSTRAINT export_requests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants (id),
    DROP CONSTRAINT export_requests_user_tenant_fkey,
    ADD CONSTRAINT export_requests_user_tenant_fkey FOREIGN KEY (user_id, tenant_id)
        REFERENCES "user".users (id, tenant_id) ON DELETE CASCADE,
    DROP CONSTRAINT export_requests_user_id_fkey,
    ADD CONSTRAINT export_requests_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES "user".users (id) ON DELETE CASCADE,
    DROP CONSTRAINT export_requests_subject_check,
    ALTER COLUMN user_id SET NOT NULL,
    DROP COLUMN subject_id;
