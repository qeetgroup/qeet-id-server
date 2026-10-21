ALTER TABLE tenant.security_policies ADD COLUMN IF NOT EXISTS ip_allowlist CIDR[] NOT NULL DEFAULT '{}';
ALTER TABLE tenant.security_policies ADD COLUMN IF NOT EXISTS ip_denylist CIDR[] NOT NULL DEFAULT '{}';
