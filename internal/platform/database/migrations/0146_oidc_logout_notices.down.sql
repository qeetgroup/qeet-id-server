DROP TABLE IF EXISTS auth.oidc_logout_deliveries;
ALTER TABLE auth.oidc_clients DROP COLUMN IF EXISTS frontchannel_logout_uri;
ALTER TABLE auth.oidc_clients DROP COLUMN IF EXISTS backchannel_logout_uri;
