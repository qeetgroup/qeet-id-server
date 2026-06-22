CREATE TABLE "user".users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenant.tenants(id),
    email               TEXT NOT NULL,
    email_verified_at   TIMESTAMPTZ,
    phone               TEXT,
    phone_verified_at   TIMESTAMPTZ,
    display_name        TEXT,
    status              TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'invited', 'suspended', 'deleted')),
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ
);

CREATE UNIQUE INDEX uq_users_tenant_email
    ON "user".users (tenant_id, LOWER(email))
    WHERE deleted_at IS NULL;

CREATE INDEX idx_users_tenant_status
    ON "user".users (tenant_id, status)
    WHERE deleted_at IS NULL;
