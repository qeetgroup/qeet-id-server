-- 0145_oidc_code_auth_time — when the person signed in, for the ID token.
--
-- An ID token carried no authentication time, so a relying party asking for a
-- fresh sign-in (prompt=login, max_age) couldn't check it got one. The code
-- records when the hosted-login sign-in it was minted in happened, and the ID
-- token reports it as auth_time.
ALTER TABLE auth.oidc_authorization_codes ADD COLUMN auth_time TIMESTAMPTZ;
