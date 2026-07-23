-- 0071_token_vault — per-tenant encrypted storage for third-party OAuth tokens (Slack/GitHub/Google/…),
-- so an agent/integration can call out on a user's behalf via GetAccessToken without handling the refresh token directly. Reuses the secrets-vault KeyProvider (KMS or static key).

-- Provider registration: endpoints + client credentials for the auth-code exchange against one third-party API.
CREATE TABLE tenant.token_vault_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    client_secret   TEXT NOT NULL,
    authorize_url   TEXT NOT NULL,
    token_url       TEXT NOT NULL,
    scopes          TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider)
);

-- One connected account per (tenant, user, provider); refresh_token is nullable (not every provider issues one).
CREATE TABLE tenant.token_vault_grants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    provider            TEXT NOT NULL,
    external_account_id TEXT,
    access_token_ct     BYTEA NOT NULL,
    access_token_nonce  BYTEA NOT NULL,
    refresh_token_ct    BYTEA,
    refresh_token_nonce BYTEA,
    token_type          TEXT NOT NULL DEFAULT 'Bearer',
    scope               TEXT,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, user_id, provider)
);

-- Single-use OAuth2 state for the connect ceremony: correlates the provider's redirect callback (no auth header) back to the (tenant, user, provider) that started it.
CREATE TABLE tenant.token_vault_connect_states (
    state       TEXT PRIMARY KEY,
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
