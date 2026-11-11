ALTER TABLE auth.oidc_connection_states DROP COLUMN IF EXISTS return_to;
ALTER TABLE auth.saml_authn_requests DROP COLUMN IF EXISTS return_to;
