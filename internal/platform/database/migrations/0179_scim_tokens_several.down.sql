-- Keeps each organisation's newest working token, the one the single-token
-- schema can hold.
DELETE FROM tenant.scim_tokens t
WHERE t.revoked_at IS NOT NULL
   OR (t.expires_at IS NOT NULL AND t.expires_at <= NOW())
   OR EXISTS (
       SELECT 1 FROM tenant.scim_tokens n
       WHERE n.tenant_id = t.tenant_id AND n.revoked_at IS NULL
         AND (n.expires_at IS NULL OR n.expires_at > NOW())
         AND (n.created_at, n.id) > (t.created_at, t.id)
   );
ALTER TABLE tenant.scim_tokens
    DROP COLUMN replaced_by,
    DROP COLUMN revoked_at,
    DROP COLUMN expires_at,
    DROP COLUMN name,
    DROP COLUMN id,
    ADD PRIMARY KEY (tenant_id);
