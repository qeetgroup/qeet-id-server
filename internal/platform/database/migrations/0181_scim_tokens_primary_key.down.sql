ALTER TABLE tenant.scim_tokens
    DROP CONSTRAINT scim_tokens_replaced_by_fkey,
    DROP CONSTRAINT scim_tokens_pkey;
