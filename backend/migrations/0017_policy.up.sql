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

-- Device trust: remember a (user, device fingerprint) pair so we can skip
-- MFA / re-auth on a trusted device.
CREATE TABLE auth.trusted_devices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    fingerprint_hash    TEXT NOT NULL,
    label               TEXT,
    last_seen_ip        INET,
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX uq_trusted_devices ON auth.trusted_devices (user_id, fingerprint_hash);
