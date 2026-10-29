-- 0188_saml_service_provider_tenant_key — a row about a service provider can
-- name it by (tenant_id, id).
--
-- The rows 9752 adds for an organisation's SAML service providers refer to one
-- by (tenant_id, id), so they can only belong to one of their own
-- organisation's. That reference needs (tenant_id, id) to be unique; the index
-- is built without blocking the table.
CREATE UNIQUE INDEX CONCURRENTLY saml_service_providers_tenant_id_id_key
    ON tenant.saml_service_providers (tenant_id, id);
