-- 0192_break_glass_members — the members who keep their own sign-in methods
-- when their organisation requires single sign-on for its domain.
--
-- A verified domain with sso_enabled, in an organisation with an active SAML
-- or LDAP connection, sends everyone on it to that identity provider: their
-- password, magic links, passkeys, password resets and self sign-up are
-- refused. An organisation's owners name a few members here who keep them, so
-- an outage of the identity provider can't lock everyone out.
CREATE TABLE tenant.break_glass_members (
    tenant_id  UUID        NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    user_id    UUID        NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    created_by UUID        REFERENCES "user".users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX idx_break_glass_members_user ON tenant.break_glass_members (user_id);

ALTER TABLE tenant.break_glass_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.break_glass_members
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
