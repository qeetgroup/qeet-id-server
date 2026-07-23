-- 0030_saml — SAML 2.0 SP-initiated SSO: one row per tenant↔IdP connection (cert validates assertions at the ACS; attrs map onto a JIT-provisioned user)

CREATE TABLE tenant.saml_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    idp_entity_id   TEXT NOT NULL,                 -- IdP issuer / EntityID
    idp_sso_url     TEXT NOT NULL,                 -- IdP SSO (HTTP-Redirect) endpoint
    idp_certificate TEXT NOT NULL,                 -- IdP signing cert (PEM or bare base64 DER)
    email_attribute TEXT NOT NULL DEFAULT '',      -- assertion attr for email ('' = use NameID)
    name_attribute  TEXT NOT NULL DEFAULT '',      -- assertion attr for display name
    status          TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'active', 'disabled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);
CREATE INDEX idx_saml_conn_tenant ON tenant.saml_connections (tenant_id);

-- One-time codes bridging a validated ACS assertion to a token pair, so the SPA never sees tokens in a URL.
CREATE TABLE auth.saml_login_codes (
    code_hash   TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
