-- OIDC clients for *our* Identity Provider role. A "client" is a downstream
-- relying party (web app, mobile, CLI) that authenticates users via Qeet.
CREATE TABLE auth.oidc_clients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT,                  -- nullable for public clients
    type            TEXT NOT NULL DEFAULT 'confidential'
        CHECK (type IN ('confidential', 'public')),
    name            TEXT NOT NULL,
    redirect_uris   TEXT[] NOT NULL DEFAULT '{}',
    post_logout_uris TEXT[] NOT NULL DEFAULT '{}',
    grant_types     TEXT[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    scopes          TEXT[] NOT NULL DEFAULT '{openid,profile,email}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.oidc_authorization_codes (
    code_hash       TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL,
    user_id         UUID NOT NULL,
    tenant_id       UUID NOT NULL,
    redirect_uri    TEXT NOT NULL,
    scopes          TEXT[] NOT NULL,
    nonce           TEXT,
    code_challenge  TEXT,
    code_challenge_method TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Consents the user has granted to a (client, scope) pair so we can skip
-- the consent screen on subsequent authorizations.
CREATE TABLE auth.oidc_consents (
    user_id     UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL,
    scopes      TEXT[] NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, client_id)
);
