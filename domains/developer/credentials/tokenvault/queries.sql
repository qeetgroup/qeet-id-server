-- Queries for the token-vault domain.
-- storeGrant (upsert with nullable []byte params) is converted below using
-- pointer types; the encrypt/decrypt/HTTP-exchange logic stays in the Service.

-- name: RegisterProvider :one
INSERT INTO tenant.token_vault_providers (tenant_id, provider, client_id, client_secret, authorize_url, token_url, scopes)
VALUES (@tenant_id, @provider, @client_id, @client_secret, @authorize_url, @token_url, @scopes)
ON CONFLICT (tenant_id, provider) DO UPDATE SET
    client_id = EXCLUDED.client_id, client_secret = EXCLUDED.client_secret,
    authorize_url = EXCLUDED.authorize_url, token_url = EXCLUDED.token_url,
    scopes = EXCLUDED.scopes, updated_at = NOW()
RETURNING id, provider, client_id, authorize_url, token_url, scopes, created_at, updated_at;

-- name: ListProviders :many
SELECT id, provider, client_id, authorize_url, token_url, scopes, created_at, updated_at
FROM tenant.token_vault_providers WHERE tenant_id = $1 ORDER BY provider;

-- name: DeleteProvider :execrows
DELETE FROM tenant.token_vault_providers WHERE tenant_id = @tenant_id AND provider = @provider;

-- GetProviderConfig fetches full config including client_secret for the
-- token-exchange; client_secret is never surfaced to end users.
-- name: GetProviderConfig :one
SELECT client_id, client_secret, authorize_url, token_url, scopes
FROM tenant.token_vault_providers WHERE tenant_id = @tenant_id AND provider = @provider;

-- name: InsertConnectState :exec
INSERT INTO tenant.token_vault_connect_states (state, tenant_id, user_id, provider, expires_at)
VALUES (@state, @tenant_id, @user_id, @provider, @expires_at);

-- DeleteConnectState atomically consumes the single-use state for the
-- FinishConnect ceremony (DELETE … RETURNING validates and consumes in one shot).
-- name: DeleteConnectState :one
DELETE FROM tenant.token_vault_connect_states WHERE state = $1
RETURNING tenant_id, user_id, provider, expires_at;

-- UpsertTokenGrant writes (or refreshes) a connected account's token pair.
-- refresh_token_ct / refresh_token_nonce are nullable: NULL means "no refresh
-- token" on insert; COALESCE preserves the existing one on update when the
-- provider omits it from the refresh response.
-- name: UpsertTokenGrant :exec
INSERT INTO tenant.token_vault_grants
    (tenant_id, user_id, provider, access_token_ct, access_token_nonce,
     refresh_token_ct, refresh_token_nonce, token_type, scope, expires_at)
VALUES (@tenant_id, @user_id, @provider, @access_token_ct, @access_token_nonce,
        @refresh_token_ct, @refresh_token_nonce, @token_type, @scope, @expires_at)
ON CONFLICT (tenant_id, user_id, provider) DO UPDATE SET
    access_token_ct = EXCLUDED.access_token_ct,
    access_token_nonce = EXCLUDED.access_token_nonce,
    refresh_token_ct = COALESCE(EXCLUDED.refresh_token_ct, tenant.token_vault_grants.refresh_token_ct),
    refresh_token_nonce = COALESCE(EXCLUDED.refresh_token_nonce, tenant.token_vault_grants.refresh_token_nonce),
    token_type = EXCLUDED.token_type,
    scope = EXCLUDED.scope,
    expires_at = EXCLUDED.expires_at,
    updated_at = NOW();

-- name: GetTokenGrant :one
SELECT access_token_ct, access_token_nonce, refresh_token_ct, refresh_token_nonce, expires_at
FROM tenant.token_vault_grants
WHERE tenant_id = @tenant_id AND user_id = @user_id AND provider = @provider;

-- name: ListGrants :many
SELECT provider, external_account_id, scope, expires_at, created_at, updated_at
FROM tenant.token_vault_grants
WHERE tenant_id = @tenant_id AND user_id = @user_id ORDER BY provider;

-- name: DeleteGrant :execrows
DELETE FROM tenant.token_vault_grants
WHERE tenant_id = @tenant_id AND user_id = @user_id AND provider = @provider;
