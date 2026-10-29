ALTER TABLE tenant.domains ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT FALSE;
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_default_domain ON tenant.domains (tenant_id) WHERE is_default;
