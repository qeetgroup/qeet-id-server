DELETE FROM "user".external_identities ei
USING tenant.oidc_connections c
WHERE ei.provider = 'oidc' AND ei.connection_id = c.id AND ei.tenant_id = c.tenant_id;

DROP TABLE auth.oidc_connection_login_codes;
DROP TABLE auth.oidc_connection_states;
DROP TABLE tenant.oidc_connections;
