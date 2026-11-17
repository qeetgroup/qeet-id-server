ALTER TABLE auth.social_login_codes DROP COLUMN IF EXISTS provider;
ALTER TABLE auth.saml_login_codes DROP COLUMN IF EXISTS connection_id;
