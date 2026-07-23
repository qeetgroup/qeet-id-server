-- 0063_risk_settings — per-tenant adaptive-MFA thresholds: medium = step-up challenge; high = force MFA even on a trusted device; force_mfa_at_level picks which level triggers the force
CREATE TABLE auth.risk_settings (
    tenant_id         uuid        NOT NULL PRIMARY KEY REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    medium_threshold  float8      NOT NULL DEFAULT 0.50 CHECK (medium_threshold BETWEEN 0.1 AND 1.0),
    high_threshold    float8      NOT NULL DEFAULT 0.80 CHECK (high_threshold   BETWEEN 0.1 AND 1.0),
    force_mfa_at_level text       NOT NULL DEFAULT 'high' CHECK (force_mfa_at_level IN ('medium','high')),
    updated_at        timestamptz NOT NULL DEFAULT NOW()
);
