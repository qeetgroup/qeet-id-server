-- 0236_oidc_client_lockout_primary_key — a lockout row is keyed by its
-- application and source network.
ALTER TABLE auth.oidc_client_auth_lockouts
    ADD CONSTRAINT oidc_client_auth_lockouts_pkey PRIMARY KEY USING INDEX oidc_client_auth_lockouts_client_network;
