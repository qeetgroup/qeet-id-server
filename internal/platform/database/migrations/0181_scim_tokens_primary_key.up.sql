-- 0181_scim_tokens_primary_key — a SCIM token is keyed by its organisation
-- and id, and the token that replaced a rotated one is of the same
-- organisation.
ALTER TABLE tenant.scim_tokens
    ADD CONSTRAINT scim_tokens_pkey PRIMARY KEY USING INDEX scim_tokens_tenant_id_id,
    ADD CONSTRAINT scim_tokens_replaced_by_fkey FOREIGN KEY (tenant_id, replaced_by)
        REFERENCES tenant.scim_tokens (tenant_id, id) ON DELETE SET NULL (replaced_by);
