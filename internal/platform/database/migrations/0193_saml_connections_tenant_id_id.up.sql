-- 0193_saml_connections_tenant_id_id — a unique (tenant_id, id) on SAML
-- connections, so the tables that belong to a connection can refer to it by
-- both and the database refuses a row pointing at another organisation's.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS saml_connections_tenant_id_id_key
    ON tenant.saml_connections (tenant_id, id);
