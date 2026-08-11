-- 0095_tenant_logo (down)
ALTER TABLE tenant.tenants DROP COLUMN IF EXISTS logo_url;
