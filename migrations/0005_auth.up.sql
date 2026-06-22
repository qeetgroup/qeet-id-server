-- Per-user password credential. Other credential types (passkey, oidc) live
-- in their own tables and are added when those features land.
CREATE TABLE auth.password_credentials (
    user_id         UUID PRIMARY KEY REFERENCES "user".users(id) ON DELETE CASCADE,
    password_hash   TEXT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A session is created at login. Access tokens reference it via sid claim;
-- revoking the session invalidates every outstanding access token via
-- the revoked_at check on refresh.
CREATE TABLE auth.sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id),
    ip              INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX idx_sessions_user ON auth.sessions (user_id);
CREATE INDEX idx_sessions_active
    ON auth.sessions (user_id)
    WHERE revoked_at IS NULL;

-- Refresh tokens are opaque; we store only their SHA-256 hash. Rotating
-- a refresh token marks the old row used and inserts a new one.
CREATE TABLE auth.refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES auth.sessions(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    replaced_by     UUID REFERENCES auth.refresh_tokens(id)
);

CREATE INDEX idx_refresh_session ON auth.refresh_tokens (session_id);
