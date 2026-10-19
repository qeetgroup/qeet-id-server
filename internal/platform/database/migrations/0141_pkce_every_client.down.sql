DROP INDEX IF EXISTS auth.idx_oidc_refresh_tokens_code;
ALTER TABLE auth.oidc_refresh_tokens DROP COLUMN IF EXISTS authorization_code_hash;
ALTER TABLE auth.oidc_clients DROP COLUMN IF EXISTS pkce_exempt_until;
