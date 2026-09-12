DROP INDEX IF EXISTS tenant.uq_tenant_default_domain;
ALTER TABLE tenant.domains
    DROP COLUMN IF EXISTS last_checked_at,
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS sso_enabled,
    DROP COLUMN IF EXISTS jit_enabled,
    DROP COLUMN IF EXISTS is_default;
