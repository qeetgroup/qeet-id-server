-- Self-serve Admin Portal: a unique, time-limited, capability-scoped link a
-- tenant admin can hand to their own IT admin (no Qeet ID account, no console
-- credentials) so that person can configure the tenant's SAML connection
-- and/or rotate its SCIM token directly. Possession of the raw token is the
-- sole credential (hashed at rest, like an invite or magic-link token); unlike
-- those, a portal link is not single-use — it's a revisitable session valid
-- until expires_at or an explicit revoke.
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
