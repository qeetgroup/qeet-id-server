-- 0185_sso_group_sync — single sign-on keeps a person's groups in step with
-- their identity provider.
--
-- A SAML connection names the assertion attribute that carries a person's
-- groups (empty: the common ones). An organisation maps an identity provider's
-- group to one of its own groups, per SAML or LDAP connection. A membership a
-- sign-in made names the connection, and sign-in adds and removes only those:
-- one an administrator, an import or SCIM made names none.
ALTER TABLE tenant.saml_connections
    ADD COLUMN groups_attribute TEXT NOT NULL DEFAULT '' CHECK (char_length(groups_attribute) <= 256);

ALTER TABLE tenant.group_members ADD COLUMN source_connection_id UUID;

CREATE TABLE tenant.sso_group_mappings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL,
    idp_group     TEXT NOT NULL CHECK (char_length(idp_group) BETWEEN 1 AND 1024),
    group_id      UUID NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT sso_group_mappings_group_id_fkey FOREIGN KEY (tenant_id, group_id)
        REFERENCES tenant.groups (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX sso_group_mappings_value
    ON tenant.sso_group_mappings (tenant_id, connection_id, lower(idp_group), group_id);

ALTER TABLE tenant.sso_group_mappings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.sso_group_mappings
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
