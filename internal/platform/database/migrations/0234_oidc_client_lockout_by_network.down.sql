DELETE FROM auth.oidc_client_auth_lockouts WHERE source_network <> '';
ALTER TABLE auth.oidc_client_auth_lockouts
    DROP COLUMN source_network,
    ADD PRIMARY KEY (client_row_id);
