-- OAuth 2.0 Device Authorization Grant (RFC 8628). For input-constrained
-- clients (CLI/TV/IoT) that can't open a browser locally: the device polls the
-- token endpoint while the user approves the request on a second device by
-- entering the user_code at the verification_uri. The device_code is the secret
-- the device polls with, so it is stored only as a hash (like authorization
-- codes / refresh tokens); the user_code is the short, human-typed value and is
-- stored in the clear for lookup. Rows are scoped to the client's tenant; the
-- approving user (bound on authorization) must belong to that tenant.
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
