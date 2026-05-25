-- Federated identities — Qeet as an OIDC/OAuth client. Each row binds one
-- of our users to one external provider account. Providers configured per
-- tenant.
CREATE TABLE tenant.social_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,           -- 'google', 'github', 'microsoft', 'okta', ...
    client_id       TEXT NOT NULL,
    client_secret   TEXT NOT NULL,           -- encrypt-at-rest in prod
    discovery_url   TEXT,                    -- OIDC discovery; empty for OAuth-only (github)
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX uq_social_tenant_provider ON tenant.social_providers (tenant_id, provider);

CREATE TABLE "user".external_identities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,
    subject         TEXT NOT NULL,
    email           TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    linked_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX uq_ext_identity_provider ON "user".external_identities (tenant_id, provider, subject);
