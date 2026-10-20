DROP INDEX IF EXISTS auth.idx_oidc_refresh_tokens_grant;
ALTER TABLE auth.oidc_refresh_tokens DROP COLUMN IF EXISTS grant_id;
