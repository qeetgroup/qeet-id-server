-- Refresh tokens for the OIDC authorization_code flow. Unlike auth.refresh_tokens
-- (session-bound, first-party), these are bound to an OIDC client and carry the
-- granted scopes so a rotated token re-issues an access/ID token that matches the
-- original grant. Rotation + reuse-detection mirrors auth.refresh_tokens.
CREATE TABLE auth.oidc_refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  TEXT NOT NULL UNIQUE,
    client_id   TEXT NOT NULL,
    user_id     UUID NOT NULL REFERENCES "user".users(id)  ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    replaced_by UUID REFERENCES auth.oidc_refresh_tokens(id),
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_oidc_refresh_client_user ON auth.oidc_refresh_tokens (client_id, user_id);
