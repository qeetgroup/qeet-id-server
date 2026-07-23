-- 0054_trusted_devices — adaptive MFA "remember this device" (opt-in via auth_policy.remember_device_enabled):
-- skip the 2nd factor on a device that previously completed MFA, for a bounded window. Device = opaque HttpOnly cookie token, stored only as a hash.
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
