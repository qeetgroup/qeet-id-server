DROP INDEX IF EXISTS auth.idx_oidc_refresh_login_session_unrevoked;
DROP INDEX IF EXISTS auth.idx_oidc_codes_login_session_unused;
ALTER TABLE auth.oidc_refresh_tokens      DROP COLUMN IF EXISTS login_session_id;
ALTER TABLE auth.oidc_authorization_codes DROP COLUMN IF EXISTS login_session_id;
DROP INDEX IF EXISTS auth.login_sessions_id_key;
ALTER TABLE auth.login_sessions DROP COLUMN IF EXISTS id;
