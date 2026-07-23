-- 0064_rate_limit_overrides — per-tenant overrides that supersede platform defaults; limit_key mirrors the router limiter names ('tenant','user','api_key')
CREATE TABLE platform.rate_limit_overrides (
    id          uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id   uuid        NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    limit_key   text        NOT NULL CHECK (limit_key IN ('tenant','user','api_key')),
    rate        float8      NOT NULL CHECK (rate > 0),
    capacity    int         NOT NULL CHECK (capacity > 0),
    updated_at  timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, limit_key)
);
