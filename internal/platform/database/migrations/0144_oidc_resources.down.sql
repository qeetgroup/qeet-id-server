ALTER TABLE auth.oidc_consent_requests DROP COLUMN IF EXISTS resource;
ALTER TABLE auth.oidc_authorization_codes DROP COLUMN IF EXISTS resource;
DROP TABLE IF EXISTS auth.oidc_resources;
