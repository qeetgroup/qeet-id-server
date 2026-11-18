-- Queries for the token-vault domain. Tokens and client secrets are stored
-- sealed; the service opens them.

-- name: ListProviders :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, provider, client_id, authorize_url, token_url, scopes, created_at, updated_at
FROM organization.token_vault_providers WHERE organization_id = $1 ORDER BY provider
LIMIT 1001;

-- UpsertProvider stores the organization's settings for a provider, replacing
-- those it had.
-- name: UpsertProvider :one
INSERT INTO organization.token_vault_providers
    (organization_id, provider, client_id, client_secret_ct, client_secret_nonce, authorize_url, token_url, scopes)
VALUES (@organization_id, @provider, @client_id, @client_secret_ct, @client_secret_nonce, @authorize_url, @token_url, @scopes)
ON CONFLICT (organization_id, provider) DO UPDATE SET
    client_id = EXCLUDED.client_id,
    client_secret_ct = EXCLUDED.client_secret_ct,
    client_secret_nonce = EXCLUDED.client_secret_nonce,
    authorize_url = EXCLUDED.authorize_url,
    token_url = EXCLUDED.token_url,
    scopes = EXCLUDED.scopes,
    updated_at = NOW()
RETURNING id, provider, client_id, authorize_url, token_url, scopes, created_at, updated_at;

-- GetProviderConfig reads what calling a provider takes: its client, sealed
-- client secret, endpoints and scopes.
-- name: GetProviderConfig :one
SELECT client_id, client_secret_ct, client_secret_nonce, authorize_url, token_url, scopes
FROM organization.token_vault_providers
WHERE organization_id = @organization_id AND provider = @provider;

-- name: DeleteProvider :execrows
DELETE FROM organization.token_vault_providers WHERE organization_id = @organization_id AND provider = @provider;

-- name: DeleteProviderGrants :exec
DELETE FROM organization.token_vault_grants WHERE organization_id = @organization_id AND provider = @provider;

-- LockProvider reads a provider's endpoints and client, locking its row until
-- the transaction ends.
-- name: LockProvider :one
SELECT client_id, authorize_url, token_url FROM organization.token_vault_providers
WHERE organization_id = @organization_id AND provider = @provider
FOR UPDATE;

-- name: ProviderHasGrants :one
SELECT EXISTS (
    SELECT 1 FROM organization.token_vault_grants WHERE organization_id = @organization_id AND provider = @provider
)::bool;

-- name: InsertConnectState :exec
INSERT INTO organization.token_vault_connect_states (state, organization_id, user_id, provider, expires_at, code_verifier)
VALUES (@state, @organization_id, @user_id, @provider, @expires_at, @code_verifier);

-- DeleteConnectState atomically consumes the single-use state for the
-- FinishConnect ceremony (DELETE … RETURNING validates and consumes in one shot).
-- name: DeleteConnectState :one
DELETE FROM organization.token_vault_connect_states WHERE state = $1
RETURNING organization_id, user_id, provider, expires_at, COALESCE(code_verifier, '')::text AS code_verifier;

-- UpsertTokenGrant writes (or refreshes) a connected account's token pair,
-- only while the provider still has the token URL and client the tokens came
-- from: it writes no row otherwise. The provider's row is share-locked, so it
-- can't change under the write. refresh_token_ct / refresh_token_nonce are
-- nullable: NULL means "no refresh token" on insert; COALESCE preserves the
-- existing one on update when the provider omits it from the refresh response.
-- name: UpsertTokenGrant :execrows
INSERT INTO organization.token_vault_grants
    (organization_id, user_id, provider, access_token_ct, access_token_nonce,
     refresh_token_ct, refresh_token_nonce, token_type, scope, expires_at)
SELECT p.organization_id, @user_id::uuid, p.provider, @access_token_ct::bytea, @access_token_nonce::bytea,
       sqlc.narg('refresh_token_ct')::bytea, sqlc.narg('refresh_token_nonce')::bytea, @token_type::text,
       sqlc.narg('scope')::text, sqlc.narg('expires_at')::timestamptz
FROM organization.token_vault_providers p
WHERE p.organization_id = @organization_id AND p.provider = @provider
  AND p.token_url = @token_url AND p.client_id = @client_id
FOR SHARE
ON CONFLICT (organization_id, user_id, provider) DO UPDATE SET
    access_token_ct = EXCLUDED.access_token_ct,
    access_token_nonce = EXCLUDED.access_token_nonce,
    refresh_token_ct = COALESCE(EXCLUDED.refresh_token_ct, organization.token_vault_grants.refresh_token_ct),
    refresh_token_nonce = COALESCE(EXCLUDED.refresh_token_nonce, organization.token_vault_grants.refresh_token_nonce),
    token_type = EXCLUDED.token_type,
    scope = EXCLUDED.scope,
    expires_at = EXCLUDED.expires_at,
    updated_at = NOW();

-- name: GetTokenGrant :one
SELECT access_token_ct, access_token_nonce, refresh_token_ct, refresh_token_nonce, expires_at
FROM organization.token_vault_grants
WHERE organization_id = @organization_id AND user_id = @user_id AND provider = @provider;

-- LockTokenGrant reads a grant to refresh it, locking its row until the
-- transaction ends.
-- name: LockTokenGrant :one
SELECT access_token_ct, access_token_nonce, refresh_token_ct, refresh_token_nonce, expires_at
FROM organization.token_vault_grants
WHERE organization_id = @organization_id AND user_id = @user_id AND provider = @provider
FOR UPDATE;

-- name: ListGrants :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT provider, external_account_id, scope, expires_at, created_at, updated_at
FROM organization.token_vault_grants
WHERE organization_id = @organization_id AND user_id = @user_id ORDER BY provider
LIMIT 1001;

-- name: DeleteGrant :execrows
DELETE FROM organization.token_vault_grants
WHERE organization_id = @organization_id AND user_id = @user_id AND provider = @provider;
