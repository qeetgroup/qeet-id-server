-- 0157_tenant_scoped_foreign_keys — a row that refers to another row of an
-- organisation can only refer to one of its own organisation's.
--
-- These references named the other row by id alone, so only the application
-- kept a role, group, conversation or earlier row from belonging to another
-- organisation. Each now names it by (tenant_id, id), with the same delete
-- behaviour as before.
ALTER TABLE rbac.roles ADD CONSTRAINT roles_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE auth.oidc_refresh_tokens ADD CONSTRAINT oidc_refresh_tokens_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE qeetai.conversations ADD CONSTRAINT conversations_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE rbac.user_roles
    DROP CONSTRAINT user_roles_role_id_fkey,
    ADD CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (tenant_id, role_id)
        REFERENCES rbac.roles (tenant_id, id) ON DELETE CASCADE;

ALTER TABLE rbac.group_roles
    DROP CONSTRAINT group_roles_role_id_fkey,
    ADD CONSTRAINT group_roles_role_id_fkey FOREIGN KEY (tenant_id, role_id)
        REFERENCES rbac.roles (tenant_id, id) ON DELETE CASCADE,
    DROP CONSTRAINT group_roles_group_id_fkey,
    ADD CONSTRAINT group_roles_group_id_fkey FOREIGN KEY (tenant_id, group_id)
        REFERENCES tenant.groups (tenant_id, id) ON DELETE CASCADE;

ALTER TABLE tenant.invites
    DROP CONSTRAINT invites_role_id_fkey,
    ADD CONSTRAINT invites_role_id_fkey FOREIGN KEY (tenant_id, role_id)
        REFERENCES rbac.roles (tenant_id, id) ON DELETE SET NULL (role_id);

ALTER TABLE tenant.group_members
    DROP CONSTRAINT group_members_group_id_fkey,
    ADD CONSTRAINT group_members_group_id_fkey FOREIGN KEY (tenant_id, group_id)
        REFERENCES tenant.groups (tenant_id, id) ON DELETE CASCADE;

ALTER TABLE qeetai.messages
    DROP CONSTRAINT messages_conversation_id_fkey,
    ADD CONSTRAINT messages_conversation_id_fkey FOREIGN KEY (tenant_id, conversation_id)
        REFERENCES qeetai.conversations (tenant_id, id) ON DELETE CASCADE;

ALTER TABLE auth.oidc_refresh_tokens
    DROP CONSTRAINT oidc_refresh_tokens_replaced_by_fkey,
    ADD CONSTRAINT oidc_refresh_tokens_replaced_by_fkey FOREIGN KEY (tenant_id, replaced_by)
        REFERENCES auth.oidc_refresh_tokens (tenant_id, id);

ALTER TABLE tenant.directory_events
    DROP CONSTRAINT directory_events_retry_of_fkey,
    ADD CONSTRAINT directory_events_retry_of_fkey FOREIGN KEY (tenant_id, retry_of)
        REFERENCES tenant.directory_events (tenant_id, id) ON DELETE SET NULL (retry_of);
