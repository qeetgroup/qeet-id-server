-- 0180_scim_tokens_tenant_id_id — a SCIM token is found by its organisation
-- and id, and an organisation's tokens are listed together.
CREATE UNIQUE INDEX CONCURRENTLY scim_tokens_tenant_id_id ON tenant.scim_tokens (tenant_id, id);
