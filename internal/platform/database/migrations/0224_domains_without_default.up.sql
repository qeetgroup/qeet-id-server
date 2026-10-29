-- 0224_domains_without_default — a domain is no longer marked its
-- organisation's default: nothing read the mark, so it was a switch that did
-- nothing.
DROP INDEX IF EXISTS tenant.uq_tenant_default_domain;
ALTER TABLE tenant.domains DROP COLUMN IF EXISTS is_default;
