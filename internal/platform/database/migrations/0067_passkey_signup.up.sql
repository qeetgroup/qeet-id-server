-- 0067_passkey_signup — hold pending-account details for passkey-first signup, before a user row exists.
-- subject_id is an ephemeral WebAuthn id (NOT the user_id FK — there's no row to reference yet); details are committed once attestation verifies.
ALTER TABLE auth.webauthn_sessions ADD COLUMN IF NOT EXISTS subject_id UUID;
ALTER TABLE auth.webauthn_sessions ADD COLUMN IF NOT EXISTS pending_email TEXT;
ALTER TABLE auth.webauthn_sessions ADD COLUMN IF NOT EXISTS pending_display_name TEXT;
ALTER TABLE auth.webauthn_sessions ADD COLUMN IF NOT EXISTS pending_tenant_id UUID REFERENCES tenant.tenants(id);
