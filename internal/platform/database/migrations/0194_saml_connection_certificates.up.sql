-- 0194_saml_connection_certificates — a SAML connection trusts several of its
-- identity provider's signing certificates at once, so the IdP can publish its
-- next certificate, switch to it and retire the old one without a sign-in
-- outage. source says whether an administrator added the certificate or the
-- IdP's metadata listed it. idp_certificate on the connection keeps the oldest.
CREATE TABLE tenant.saml_connection_certificates (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL,
    certificate   TEXT NOT NULL,                 -- PEM or bare base64 DER
    source        TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'metadata')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES tenant.saml_connections (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_saml_conn_certs_connection
    ON tenant.saml_connection_certificates (tenant_id, connection_id);

INSERT INTO tenant.saml_connection_certificates (tenant_id, connection_id, certificate, created_at)
SELECT tenant_id, id, idp_certificate, created_at FROM tenant.saml_connections;

ALTER TABLE tenant.saml_connection_certificates ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.saml_connection_certificates
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
