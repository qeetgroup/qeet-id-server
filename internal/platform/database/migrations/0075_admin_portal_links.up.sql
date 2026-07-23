-- 0075_admin_portal_links — capability-scoped, time-limited link a tenant admin hands to their IT admin (no Qeet account) to set up SAML / rotate SCIM.
-- Possession of the raw token is the sole credential (hashed at rest); unlike invite/magic-link tokens it's not single-use — a revisitable session until expires_at or revoke.
CREATE TABLE tenant.admin_portal_links (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    capabilities TEXT[] NOT NULL,
    created_by   UUID REFERENCES "user".users(id) ON DELETE SET NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_admin_portal_links_tenant ON tenant.admin_portal_links (tenant_id);
