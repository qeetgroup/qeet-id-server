-- Adaptive MFA: trusted ("remembered") devices. When a tenant opts in
-- (auth_policy.remember_device_enabled) an enrolled user can skip the second
-- factor on a device where they previously completed MFA, for a bounded window.
-- A device is identified by an opaque HttpOnly cookie token; only its hash is
-- stored (like refresh tokens / SSO sessions). New/unknown devices still get
-- the MFA step-up.
CREATE TABLE auth.trusted_devices (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    tenant_id    UUID,
    token_hash   TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_trusted_devices_user ON auth.trusted_devices (user_id);

-- Per-tenant gate (off by default: MFA stays always-on unless a tenant opts in).
ALTER TABLE tenant.auth_policy
    ADD COLUMN remember_device_enabled BOOLEAN NOT NULL DEFAULT false;
