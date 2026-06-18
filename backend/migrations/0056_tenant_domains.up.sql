-- Verified email domains for a tenant (B2B SSO onboarding). A tenant claims a
-- domain, proves ownership via a DNS TXT record, and the verified domain can
-- later gate org SSO / JIT provisioning. DNS verification is an explicit admin
-- action (no implicit trust).
CREATE TABLE tenant.domains (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    domain             TEXT NOT NULL,
    verification_token TEXT NOT NULL,
    verified_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A tenant can't list the same domain twice.
CREATE UNIQUE INDEX uq_tenant_domain ON tenant.domains (tenant_id, lower(domain));
-- Only one tenant may hold a *verified* claim on a given domain.
CREATE UNIQUE INDEX uq_verified_domain
    ON tenant.domains (lower(domain))
    WHERE verified_at IS NOT NULL;
