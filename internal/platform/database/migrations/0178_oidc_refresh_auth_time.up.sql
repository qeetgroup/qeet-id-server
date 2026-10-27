-- 0178_oidc_refresh_auth_time — when the person signed in, for a renewed ID
-- token.
--
-- A refresh issued the ID token again without auth_time, although OpenID
-- Connect Core 12.2 says a renewed ID token reports the original sign-in. A
-- grant records the authentication time of the code it was redeemed from, and
-- every renewal carries it forward. Grants issued before this have none.
ALTER TABLE auth.oidc_refresh_tokens ADD COLUMN auth_time TIMESTAMPTZ;
