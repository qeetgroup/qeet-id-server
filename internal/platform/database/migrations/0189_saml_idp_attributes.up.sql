-- 0189_saml_idp_attributes — what an organisation's SAML apps are told about
-- a person.
--
-- attributes lists the attributes a service provider receives, each a SAML
-- name and the source of its values; the default is the email and name
-- attributes every service provider received before. A persistent NameID was
-- the email, which changes; it is now a random value made the first time a
-- person signs in to the service provider and kept, whatever their email,
-- until either goes. A service provider set to a persistent NameID names it.
ALTER TABLE tenant.saml_service_providers
    ADD COLUMN attributes JSONB NOT NULL
        DEFAULT '[{"name": "email", "source": "email"}, {"name": "name", "source": "display_name"}]'::jsonb;

UPDATE tenant.saml_service_providers SET name_id_attribute = 'persistent_id'
WHERE name_id_format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
  AND name_id_attribute NOT IN ('persistent_id', 'user_id');

CREATE TABLE tenant.saml_idp_persistent_ids (
    tenant_id  UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    sp_id      UUID NOT NULL,
    user_id    UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    name_id    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, sp_id, user_id),
    UNIQUE (tenant_id, sp_id, name_id),
    FOREIGN KEY (tenant_id, sp_id)
        REFERENCES tenant.saml_service_providers (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_saml_idp_persistent_ids_user ON tenant.saml_idp_persistent_ids (user_id);

ALTER TABLE tenant.saml_idp_persistent_ids ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.saml_idp_persistent_ids
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
