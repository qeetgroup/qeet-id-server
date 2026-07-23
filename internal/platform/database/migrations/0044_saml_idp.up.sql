-- 0044_saml_idp — SAML 2.0 IdP side (Qeet as SSO source): one row per downstream SP; inbound AuthnRequest Issuer matches entity_id, then a signed assertion is POSTed to acs_url

CREATE TABLE tenant.saml_service_providers (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    entity_id         TEXT NOT NULL,                 -- SP EntityID / assertion Audience
    acs_url           TEXT NOT NULL,                 -- AssertionConsumerService (HTTP-POST)
    name_id_format    TEXT NOT NULL
        DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    name_id_attribute TEXT NOT NULL DEFAULT 'email', -- user field mapped to NameID
    certificate       TEXT NOT NULL DEFAULT '',      -- optional SP cert (future: signed AuthnRequest)
    status            TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'active', 'disabled')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at     TIMESTAMPTZ,
    UNIQUE (tenant_id, entity_id)
);
CREATE INDEX idx_saml_sp_tenant ON tenant.saml_service_providers (tenant_id);
CREATE INDEX idx_saml_sp_entity ON tenant.saml_service_providers (entity_id);
