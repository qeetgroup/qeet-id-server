-- 0218_compliance_owners_audits — who owns each compliance control in an
-- organisation, and the external audits and certificates it has been through.
CREATE TABLE tenant.compliance_control_owners (
    tenant_id  UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL CHECK (char_length(control_id) BETWEEN 1 AND 64),
    user_id    UUID NOT NULL,
    updated_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, control_id)
);

ALTER TABLE tenant.compliance_control_owners ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.compliance_control_owners
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

-- kind is an 'audit' an external body carried out, or a 'certificate' one
-- issued; body names it, scope what it covered.
CREATE TABLE tenant.compliance_audits (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    framework  TEXT NOT NULL CHECK (framework IN ('soc2', 'iso27001')),
    kind       TEXT NOT NULL CHECK (kind IN ('audit', 'certificate')),
    body       TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 200),
    scope      TEXT NOT NULL DEFAULT '' CHECK (char_length(scope) <= 2000),
    reference  TEXT NOT NULL DEFAULT '' CHECK (char_length(reference) <= 200),
    issued_on  DATE NOT NULL,
    expires_on DATE CHECK (expires_on IS NULL OR expires_on >= issued_on),
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_audits_tenant ON tenant.compliance_audits (tenant_id, issued_on DESC);

ALTER TABLE tenant.compliance_audits ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.compliance_audits
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
