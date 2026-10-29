-- 0187_oidc_connections — an organisation signs in through its own OpenID
-- Connect identity provider (Microsoft Entra ID, Okta, Google Workspace, …).
--
-- One row per connection; the client secret is sealed with the deployment's
-- envelope key. A sign-in's state (PKCE verifier, nonce) and the one-time code
-- it hands the console live in auth.*, keyed by their hashes and owned by the
-- connection, which names the organisation.
CREATE TABLE tenant.oidc_connections (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    name                   TEXT NOT NULL,
    issuer                 TEXT NOT NULL,                  -- the iss an ID token must carry
    discovery_url          TEXT NOT NULL DEFAULT '',       -- '' = issuer + /.well-known/openid-configuration
    client_id              TEXT NOT NULL,
    client_secret_ct       BYTEA NOT NULL,
    client_secret_nonce    BYTEA NOT NULL,
    encryption_version     SMALLINT NOT NULL DEFAULT 1,
    scopes                 TEXT[] NOT NULL DEFAULT ARRAY['openid', 'email', 'profile'],
    allowed_idp_tenant_ids TEXT[] NOT NULL DEFAULT '{}',   -- tid values a multi-tenant issuer (Entra) may sign for
    email_claim            TEXT NOT NULL DEFAULT 'email',
    name_claim             TEXT NOT NULL DEFAULT 'name',
    given_name_claim       TEXT NOT NULL DEFAULT 'given_name',
    family_name_claim      TEXT NOT NULL DEFAULT 'family_name',
    groups_claim           TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'active', 'disabled')),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at          TIMESTAMPTZ
);
CREATE INDEX idx_oidc_conn_tenant ON tenant.oidc_connections (tenant_id);

ALTER TABLE tenant.oidc_connections ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.oidc_connections
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

-- A sign-in begun at the login endpoint, spent by its callback.
CREATE TABLE auth.oidc_connection_states (
    state_hash    TEXT PRIMARY KEY,
    connection_id UUID NOT NULL REFERENCES tenant.oidc_connections(id) ON DELETE CASCADE,
    code_verifier TEXT NOT NULL,
    nonce_hash    TEXT NOT NULL,
    redirect_uri  TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX oidc_connection_states_expiry ON auth.oidc_connection_states (expires_at);

-- One-time codes bridging a validated ID token to a token pair, so the console
-- never sees tokens in a URL.
CREATE TABLE auth.oidc_connection_login_codes (
    code_hash     TEXT PRIMARY KEY,
    connection_id UUID NOT NULL REFERENCES tenant.oidc_connections(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX oidc_connection_login_codes_expiry ON auth.oidc_connection_login_codes (expires_at);
