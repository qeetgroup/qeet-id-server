-- 0190_saml_idp_assignments — who may sign in to an organisation's SAML apps.
--
-- Every person whose home is the organisation could sign in to every one of
-- its service providers. One with assignment_required now signs in only the
-- people assigned to it, themselves or through a group of the organisation
-- they belong to; the others still sign in all of them.
ALTER TABLE tenant.saml_service_providers
    ADD COLUMN assignment_required BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE tenant.saml_sp_user_assignments (
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    sp_id       UUID NOT NULL,
    user_id     UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID,
    PRIMARY KEY (tenant_id, sp_id, user_id),
    FOREIGN KEY (tenant_id, sp_id)
        REFERENCES tenant.saml_service_providers (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_saml_sp_user_assignments_user ON tenant.saml_sp_user_assignments (user_id);

CREATE TABLE tenant.saml_sp_group_assignments (
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    sp_id       UUID NOT NULL,
    group_id    UUID NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID,
    PRIMARY KEY (tenant_id, sp_id, group_id),
    FOREIGN KEY (tenant_id, sp_id)
        REFERENCES tenant.saml_service_providers (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, group_id)
        REFERENCES tenant.groups (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_saml_sp_group_assignments_group ON tenant.saml_sp_group_assignments (tenant_id, group_id);

ALTER TABLE tenant.saml_sp_user_assignments ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.saml_sp_user_assignments
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.saml_sp_group_assignments ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.saml_sp_group_assignments
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
