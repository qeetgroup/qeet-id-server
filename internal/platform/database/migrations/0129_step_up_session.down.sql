DROP TRIGGER IF EXISTS clear_step_ups_on_password_change ON auth.password_credentials;
DROP FUNCTION IF EXISTS auth.clear_step_ups_on_password_change();
ALTER TABLE tenant.security_policies
    DROP COLUMN IF EXISTS step_up_methods,
    DROP COLUMN IF EXISTS step_up_window;
DELETE FROM auth.mfa_verifications;
DROP INDEX IF EXISTS auth.idx_mfa_verifications_user;
ALTER TABLE auth.mfa_verifications DROP CONSTRAINT mfa_verifications_pkey;
ALTER TABLE auth.mfa_verifications DROP COLUMN session_id;
ALTER TABLE auth.mfa_verifications ADD PRIMARY KEY (user_id);
