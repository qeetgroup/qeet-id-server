-- CSRF state + PKCE verifier for the upstream OAuth round-trip. Single-use and
-- short-lived: a row is written on /social/{provider}/start and deleted when the
-- matching /callback consumes it.
CREATE TABLE auth.social_oauth_states (
    state_hash    TEXT PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    provider      TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    redirect_uri  TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One-time application code minted after a successful upstream login. The SPA
-- trades it at /social/exchange for a Qeet token pair, so tokens never travel
-- in a redirect URL.
CREATE TABLE auth.social_login_codes (
    code_hash   TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES "user".users(id)   ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants(id)  ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
