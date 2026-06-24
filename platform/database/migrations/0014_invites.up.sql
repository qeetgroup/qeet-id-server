CREATE TABLE tenant.invites (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    role_id         UUID REFERENCES rbac.roles(id) ON DELETE SET NULL,
    invited_by      UUID,
    token_hash      TEXT NOT NULL UNIQUE,
    status          TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    expires_at      TIMESTAMPTZ NOT NULL,
    accepted_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_invites_tenant ON tenant.invites (tenant_id, status);
CREATE INDEX idx_invites_email ON tenant.invites (tenant_id, LOWER(email));
