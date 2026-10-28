-- 0197_account_deletion — deleting an account for good keeps the record of its
-- erasure, and nothing the account is named in stops the deletion.
--
-- Deleting an account (the retention purge, or purging it from the deleted
-- list) failed while the account sponsored an agent or had reviewed an
-- application, and otherwise took its erasure request with it. Now the agent
-- and the application forget the account; the erasure request keeps the
-- account's ID in subject_id; the account's personal API keys go with it
-- instead of becoming organisation keys; and so do its role memberships, which
-- nothing removed before. A data export's payload can now be deleted, leaving
-- the request 'expired'.

ALTER TABLE auth.agents
    DROP CONSTRAINT agents_sponsor_user_id_fkey,
    ADD CONSTRAINT agents_sponsor_user_id_fkey FOREIGN KEY (sponsor_user_id)
        REFERENCES "user".users (id) ON DELETE SET NULL;

ALTER TABLE auth.oidc_clients
    DROP CONSTRAINT oidc_clients_reviewed_by_fkey,
    ADD CONSTRAINT oidc_clients_reviewed_by_fkey FOREIGN KEY (reviewed_by)
        REFERENCES "user".users (id) ON DELETE SET NULL;

ALTER TABLE auth.api_keys
    DROP CONSTRAINT api_keys_user_id_fkey,
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES "user".users (id) ON DELETE CASCADE;

DELETE FROM rbac.user_roles ur
WHERE NOT EXISTS (SELECT 1 FROM "user".users u WHERE u.id = ur.user_id);
ALTER TABLE rbac.user_roles
    ADD CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES "user".users (id) ON DELETE CASCADE;

ALTER TABLE "user".purge_requests ADD COLUMN subject_id UUID;
UPDATE "user".purge_requests SET subject_id = user_id;
ALTER TABLE "user".purge_requests
    ALTER COLUMN subject_id SET NOT NULL,
    ALTER COLUMN user_id DROP NOT NULL,
    ADD CONSTRAINT purge_requests_subject_check CHECK (user_id IS NULL OR user_id = subject_id),
    DROP CONSTRAINT purge_requests_user_id_fkey,
    ADD CONSTRAINT purge_requests_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES "user".users (id) ON DELETE SET NULL,
    DROP CONSTRAINT purge_requests_user_tenant_fkey,
    ADD CONSTRAINT purge_requests_user_tenant_fkey FOREIGN KEY (user_id, tenant_id)
        REFERENCES "user".users (id, tenant_id) ON DELETE SET NULL (user_id);

ALTER TABLE "user".export_requests
    DROP CONSTRAINT export_requests_status_check,
    ADD CONSTRAINT export_requests_status_check
        CHECK (status IN ('pending', 'ready', 'failed', 'expired'));
