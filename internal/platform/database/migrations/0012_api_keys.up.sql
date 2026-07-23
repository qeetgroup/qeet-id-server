-- 0012_api_keys — tenant API keys (prefix lookup + hashed remainder)
CREATE TABLE auth.api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES "user".users(id) ON DELETE SET NULL,
    name            TEXT NOT NULL,
    prefix          TEXT NOT NULL,        -- first 8 chars, used for lookup
    key_hash        TEXT NOT NULL,        -- bcrypt of the remainder
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_api_keys_tenant ON auth.api_keys (tenant_id);
CREATE INDEX idx_api_keys_prefix ON auth.api_keys (prefix) WHERE revoked_at IS NULL;
