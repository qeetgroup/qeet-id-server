-- 0013_service_principals — machine clients authenticating with a bcrypt-hashed client_secret
CREATE TABLE auth.service_principals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    secret_hash     TEXT NOT NULL,        -- bcrypt(client_secret)
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    disabled_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX uq_service_principals_tenant_name
    ON auth.service_principals (tenant_id, LOWER(name));
