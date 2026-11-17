-- 0235_oidc_client_lockout_network_key — a lockout row is found by its
-- application and source network.
CREATE UNIQUE INDEX CONCURRENTLY oidc_client_auth_lockouts_client_network
    ON auth.oidc_client_auth_lockouts (client_row_id, source_network);
