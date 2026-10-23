ALTER TABLE tenant.directory_events
    DROP CONSTRAINT directory_events_retry_of_fkey,
    ADD CONSTRAINT directory_events_retry_of_fkey FOREIGN KEY (retry_of)
        REFERENCES tenant.directory_events (id) ON DELETE SET NULL;

ALTER TABLE auth.oidc_refresh_tokens
    DROP CONSTRAINT oidc_refresh_tokens_replaced_by_fkey,
    ADD CONSTRAINT oidc_refresh_tokens_replaced_by_fkey FOREIGN KEY (replaced_by)
        REFERENCES auth.oidc_refresh_tokens (id);

ALTER TABLE qeetai.messages
    DROP CONSTRAINT messages_conversation_id_fkey,
    ADD CONSTRAINT messages_conversation_id_fkey FOREIGN KEY (conversation_id)
        REFERENCES qeetai.conversations (id) ON DELETE CASCADE;

ALTER TABLE tenant.group_members
    DROP CONSTRAINT group_members_group_id_fkey,
    ADD CONSTRAINT group_members_group_id_fkey FOREIGN KEY (group_id)
        REFERENCES tenant.groups (id) ON DELETE CASCADE;

ALTER TABLE tenant.invites
    DROP CONSTRAINT invites_role_id_fkey,
    ADD CONSTRAINT invites_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES rbac.roles (id) ON DELETE SET NULL;

ALTER TABLE rbac.group_roles
    DROP CONSTRAINT group_roles_group_id_fkey,
    ADD CONSTRAINT group_roles_group_id_fkey FOREIGN KEY (group_id)
        REFERENCES tenant.groups (id) ON DELETE CASCADE,
    DROP CONSTRAINT group_roles_role_id_fkey,
    ADD CONSTRAINT group_roles_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES rbac.roles (id) ON DELETE CASCADE;

ALTER TABLE rbac.user_roles
    DROP CONSTRAINT user_roles_role_id_fkey,
    ADD CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES rbac.roles (id) ON DELETE CASCADE;

ALTER TABLE qeetai.conversations DROP CONSTRAINT conversations_tenant_id_id_key;
ALTER TABLE auth.oidc_refresh_tokens DROP CONSTRAINT oidc_refresh_tokens_tenant_id_id_key;
ALTER TABLE rbac.roles DROP CONSTRAINT roles_tenant_id_id_key;
