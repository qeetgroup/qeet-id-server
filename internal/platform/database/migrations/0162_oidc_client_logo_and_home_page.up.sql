-- 0162_oidc_client_logo_and_home_page — show people which application they
-- are signing in to.
--
-- The hosted sign-in page named the application and nothing else. An
-- organisation's admin may now register its logo and home page, which the page
-- shows; it never takes them from the sign-in link, whose redirect_uri is
-- whatever the link says. Named as in OpenID Connect Dynamic Client
-- Registration.
ALTER TABLE auth.oidc_clients ADD COLUMN logo_uri TEXT
    CHECK (logo_uri IS NULL OR (logo_uri LIKE 'https://%' AND length(logo_uri) <= 2048));
ALTER TABLE auth.oidc_clients ADD COLUMN client_uri TEXT
    CHECK (client_uri IS NULL OR (client_uri LIKE 'https://%' AND length(client_uri) <= 2048));
