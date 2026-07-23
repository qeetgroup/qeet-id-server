-- 0074_ciba — OIDC CIBA (Client-Initiated Backchannel Auth), poll mode: client names the user via login_hint (no redirect), user approves out-of-band, client polls with auth_req_id.
-- Backchannel counterpart of the device grant (auth.oidc_device_codes), but the user is known up front rather than via a human-typed code.
CREATE TABLE auth.oidc_ciba_requests (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_req_id_hash TEXT NOT NULL UNIQUE,
    client_id        TEXT NOT NULL,
    tenant_id        UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    scopes           TEXT[] NOT NULL DEFAULT '{}',
    binding_message  TEXT,
    status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'authorized', 'denied')),
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_polled_at   TIMESTAMPTZ,
    consumed_at      TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ NOT NULL,
    approved_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ciba_tenant ON auth.oidc_ciba_requests (tenant_id);
CREATE INDEX idx_ciba_user_pending ON auth.oidc_ciba_requests (user_id) WHERE status = 'pending';
