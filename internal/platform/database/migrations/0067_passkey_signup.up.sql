-- Support a passkey-first signup ceremony: no user row exists yet when the
-- ceremony begins, so webauthn_sessions needs somewhere to hold the ephemeral
-- WebAuthn subject id (NOT the real user_id FK — no row exists to reference)
-- plus the pending account details, filled in once attestation verifies.
ALTER TABLE auth.webauthn_sessions ADD COLUMN IF NOT EXISTS subject_id UUID;
ALTER TABLE auth.webauthn_sessions ADD COLUMN IF NOT EXISTS pending_email TEXT;
ALTER TABLE auth.webauthn_sessions ADD COLUMN IF NOT EXISTS pending_display_name TEXT;
ALTER TABLE auth.webauthn_sessions ADD COLUMN IF NOT EXISTS pending_tenant_id UUID REFERENCES tenant.tenants(id);
