-- Per-tenant authentication policy: password complexity rules and which
-- login methods the tenant permits. One row per tenant; absence means defaults.
-- Password complexity is enforced on tenant-scoped password changes.

CREATE TABLE tenant.auth_policy (
    tenant_id                  UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    password_enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    password_min_length        INT     NOT NULL DEFAULT 8 CHECK (password_min_length BETWEEN 8 AND 128),
    password_require_uppercase BOOLEAN NOT NULL DEFAULT FALSE,
    password_require_number    BOOLEAN NOT NULL DEFAULT FALSE,
    password_require_symbol    BOOLEAN NOT NULL DEFAULT FALSE,
    magic_link_enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    passkey_enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    otp_email_enabled          BOOLEAN NOT NULL DEFAULT FALSE,
    otp_sms_enabled            BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
