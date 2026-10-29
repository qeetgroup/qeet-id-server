-- 0205_oidc_client_web_origins — the web origins a browser application calls
-- the OAuth endpoints from.
--
-- A single-page application calls the token, userinfo, revocation and
-- introspection endpoints from the browser, which needs its origin allowed by
-- CORS. Each application lists its origins; NULL means the origins of its
-- redirect URIs, so most need set nothing.
ALTER TABLE auth.oidc_clients ADD COLUMN web_origins TEXT[];
