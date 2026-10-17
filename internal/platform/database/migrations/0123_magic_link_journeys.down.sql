ALTER TABLE auth.magic_links DROP COLUMN IF EXISTS return_to;
ALTER TABLE auth.magic_links DROP COLUMN IF EXISTS app;
DELETE FROM auth.magic_links WHERE tenant_id IS NULL;
ALTER TABLE auth.magic_links ALTER COLUMN tenant_id SET NOT NULL;
