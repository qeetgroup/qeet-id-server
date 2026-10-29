UPDATE "user".export_requests SET status = 'failed', error = 'expired' WHERE status = 'expired';
ALTER TABLE "user".export_requests
    DROP CONSTRAINT export_requests_status_check,
    ADD CONSTRAINT export_requests_status_check CHECK (status IN ('pending', 'ready', 'failed'));

DELETE FROM "user".purge_requests WHERE user_id IS NULL;
ALTER TABLE "user".purge_requests
    DROP CONSTRAINT purge_requests_user_tenant_fkey,
    ADD CONSTRAINT purge_requests_user_tenant_fkey FOREIGN KEY (user_id, tenant_id)
        REFERENCES "user".users (id, tenant_id) ON DELETE CASCADE,
    DROP CONSTRAINT purge_requests_user_id_fkey,
    ADD CONSTRAINT purge_requests_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES "user".users (id) ON DELETE CASCADE,
    DROP CONSTRAINT purge_requests_subject_check,
    ALTER COLUMN user_id SET NOT NULL,
    DROP COLUMN subject_id;

ALTER TABLE rbac.user_roles DROP CONSTRAINT user_roles_user_id_fkey;

ALTER TABLE auth.api_keys
    DROP CONSTRAINT api_keys_user_id_fkey,
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES "user".users (id) ON DELETE SET NULL;

ALTER TABLE auth.oidc_clients
    DROP CONSTRAINT oidc_clients_reviewed_by_fkey,
    ADD CONSTRAINT oidc_clients_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES "user".users (id);

ALTER TABLE auth.agents
    DROP CONSTRAINT agents_sponsor_user_id_fkey,
    ADD CONSTRAINT agents_sponsor_user_id_fkey FOREIGN KEY (sponsor_user_id) REFERENCES "user".users (id);
