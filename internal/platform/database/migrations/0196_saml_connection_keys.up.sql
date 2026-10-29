-- 0196_saml_connection_keys — each SAML connection has its own service
-- provider key pair, so its IdP can encrypt the assertions it sends. The
-- certificate is published in the connection's SP metadata; the PKCS #8
-- private key is envelope-encrypted, bound to the organisation and connection.
CREATE TABLE tenant.saml_connection_keys (
    connection_id UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    certificate   TEXT NOT NULL,
    key_ct        BYTEA NOT NULL,
    key_nonce     BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES tenant.saml_connections (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE tenant.saml_connection_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.saml_connection_keys
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
