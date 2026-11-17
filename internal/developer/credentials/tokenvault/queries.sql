-- Queries for the token-vault domain.
-- storeGrant (upsert with nullable []byte params) is converted below using
-- pointer types; the encrypt/decrypt/HTTP-exchange logic stays in the Service.

-- name: ListProviders :many
SELECT id, provider, client_id, authorize_url, token_url, scopes, created_at, updated_at
FROM tenant.token_vault_providers WHERE tenant_id = $1 ORDER BY provider;

-- name: DeleteProvider :execrows
DELETE FROM tenant.token_vault_providers WHERE tenant_id = @tenant_id AND provider = @provider;

-- name: DeleteProviderGrants :exec
DELETE FROM tenant.token_vault_grants WHERE tenant_id = @tenant_id AND provider = @provider;

-- LockProvider reads a provider's endpoints and client, locking its row until
-- the transaction ends.
-- name: LockProvider :one
SELECT client_id, authorize_url, token_url FROM tenant.token_vault_providers
WHERE tenant_id = @tenant_id AND provider = @provider
FOR UPDATE;

-- name: ProviderHasGrants :one
SELECT EXISTS (
    SELECT 1 FROM tenant.token_vault_grants WHERE tenant_id = @tenant_id AND provider = @provider
)::bool;

-- name: InsertConnectState :exec
INSERT INTO tenant.token_vault_connect_states (state, tenant_id, user_id, provider, expires_at, code_verifier)
VALUES (@state, @tenant_id, @user_id, @provider, @expires_at, @code_verifier);

-- DeleteConnectState atomically consumes the single-use state for the
-- FinishConnect ceremony (DELETE … RETURNING validates and consumes in one shot).
-- name: DeleteConnectState :one
DELETE FROM tenant.token_vault_connect_states WHERE state = $1
RETURNING tenant_id, user_id, provider, expires_at, COALESCE(code_verifier, '')::text AS code_verifier;

-- UpsertTokenGrant writes (or refreshes) a connected account's token pair,
-- only while the provider still has the token URL and client the tokens came
-- from: it writes no row otherwise. The provider's row is share-locked, so it
-- can't change under the write. refresh_token_ct / refresh_token_nonce are
-- nullable: NULL means "no refresh token" on insert; COALESCE preserves the
-- existing one on update when the provider omits it from the refresh response.
-- name: UpsertTokenGrant :execrows
INSERT INTO tenant.token_vault_grants
    (tenant_id, user_id, provider, access_token_ct, access_token_nonce,
     refresh_token_ct, refresh_token_nonce, token_type, scope, expires_at)
SELECT p.tenant_id, @user_id::uuid, p.provider, @access_token_ct::bytea, @access_token_nonce::bytea,
       sqlc.narg('refresh_token_ct')::bytea, sqlc.narg('refresh_token_nonce')::bytea, @token_type::text,
       sqlc.narg('scope')::text, sqlc.narg('expires_at')::timestamptz
FROM tenant.token_vault_providers p
WHERE p.tenant_id = @tenant_id AND p.provider = @provider
  AND p.token_url = @token_url AND p.client_id = @client_id
FOR SHARE
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

-- LockTokenGrant reads a grant to refresh it, locking its row until the
-- transaction ends.
-- name: LockTokenGrant :one
SELECT access_token_ct, access_token_nonce, refresh_token_ct, refresh_token_nonce, expires_at
FROM tenant.token_vault_grants
WHERE tenant_id = @tenant_id AND user_id = @user_id AND provider = @provider
FOR UPDATE;

-- name: ListGrants :many
SELECT provider, external_account_id, scope, expires_at, created_at, updated_at
FROM tenant.token_vault_grants
WHERE tenant_id = @tenant_id AND user_id = @user_id ORDER BY provider;

-- name: DeleteGrant :execrows
DELETE FROM tenant.token_vault_grants
WHERE tenant_id = @tenant_id AND user_id = @user_id AND provider = @provider;
