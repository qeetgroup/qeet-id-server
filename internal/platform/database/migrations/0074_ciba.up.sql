-- OpenID Connect CIBA (Client-Initiated Backchannel Authentication) — poll
-- mode. A client identifies the user via login_hint (no browser redirect);
-- the user gets an async, out-of-band consent prompt (in-app notification)
-- and approves/denies it; the client polls the token endpoint with
-- auth_req_id meanwhile. Structurally the backchannel counterpart of the
-- device grant (auth.oidc_device_codes) — poll/interval/status/consumed_at
-- all mirror that table — except the user is already known up front instead
-- of being resolved via a human-typed code.
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
