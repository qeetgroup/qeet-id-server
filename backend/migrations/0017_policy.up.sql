-- Per-tenant security policy: IP allow/deny, session lifetimes, password
-- requirements. CIDRs are stored as inet[] for fast containment checks.
CREATE TABLE tenant.security_policies (
    tenant_id           UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    ip_allowlist        CIDR[] NOT NULL DEFAULT '{}',
    ip_denylist         CIDR[] NOT NULL DEFAULT '{}',
    password_min_length INTEGER NOT NULL DEFAULT 8,
    password_complexity TEXT NOT NULL DEFAULT 'standard'
        CHECK (password_complexity IN ('relaxed', 'standard', 'strict')),
    session_max_age     INTERVAL NOT NULL DEFAULT INTERVAL '30 days',
    mfa_enforcement     TEXT NOT NULL DEFAULT 'optional'
        CHECK (mfa_enforcement IN ('optional', 'required', 'admin_only')),
    settings            JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- NOTE: auth.trusted_devices is created later in 0054_trusted_devices (the
-- adaptive-MFA "remember this device" feature, token_hash-based). An earlier
-- fingerprint-based draft of the table used to live here, but it was unused and
-- collided with 0054 on a clean migrate, so it was removed.
