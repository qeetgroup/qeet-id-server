-- 0048_device_authorization — OAuth Device Authorization Grant (RFC 8628) for input-constrained clients (CLI/TV/IoT).
-- device_code is the polling secret (stored hashed); user_code is short and human-typed (stored cleartext for lookup). Rows scoped to the client's tenant.
CREATE TABLE auth.oidc_device_codes (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash TEXT NOT NULL UNIQUE,
    user_code        TEXT NOT NULL UNIQUE,
    client_id        TEXT NOT NULL,
    tenant_id        UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    user_id          UUID REFERENCES "user".users(id) ON DELETE CASCADE,
    scopes           TEXT[] NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'authorized', 'denied')),
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_polled_at   TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ NOT NULL,
    approved_at      TIMESTAMPTZ,
    consumed_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX oidc_device_codes_user_code_idx        ON auth.oidc_device_codes (user_code);
CREATE INDEX oidc_device_codes_device_code_hash_idx ON auth.oidc_device_codes (device_code_hash);
CREATE INDEX oidc_device_codes_expires_at_idx       ON auth.oidc_device_codes (expires_at);
