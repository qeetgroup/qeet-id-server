ALTER TABLE auth.webauthn_sessions DROP COLUMN IF EXISTS pending_tenant_id;
ALTER TABLE auth.webauthn_sessions DROP COLUMN IF EXISTS pending_display_name;
ALTER TABLE auth.webauthn_sessions DROP COLUMN IF EXISTS pending_email;
ALTER TABLE auth.webauthn_sessions DROP COLUMN IF EXISTS subject_id;
