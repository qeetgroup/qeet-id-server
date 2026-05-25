CREATE TABLE tenant.tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'deleted')),
    plan            TEXT NOT NULL DEFAULT 'free',
    region          TEXT NOT NULL DEFAULT 'us-east-1',
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX uq_tenants_slug ON tenant.tenants (LOWER(slug));
CREATE INDEX idx_tenants_status ON tenant.tenants (status) WHERE deleted_at IS NULL;
