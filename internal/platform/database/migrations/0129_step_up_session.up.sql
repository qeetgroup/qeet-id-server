-- 0129_step_up_session — a step-up proves something about the session that
-- earned it, not about the person.
--
-- auth.mfa_verifications is keyed by session: a second factor proved in one
-- session no longer unlocks sensitive actions in any other, and a session that
-- ends (revoked, expired, deleted) takes its step-up with it. The rows already
-- there are one per person and at most minutes old; they cannot be given a
-- session, so they are dropped and anyone mid step-up is asked once more.
--
-- tenant.security_policies.step_up_window: how long a step-up lasts, between
-- 1 and 60 minutes (5 by default). step_up_methods: the factor types that count
-- as a step-up; NULL means every factor does.
--
-- A changed password clears the person's step-ups in every session.
DELETE FROM auth.mfa_verifications;
ALTER TABLE auth.mfa_verifications DROP CONSTRAINT mfa_verifications_pkey;
ALTER TABLE auth.mfa_verifications
    ADD COLUMN session_id UUID NOT NULL REFERENCES auth.sessions(id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_verifications ADD PRIMARY KEY (session_id);
CREATE INDEX idx_mfa_verifications_user ON auth.mfa_verifications (user_id);

ALTER TABLE tenant.security_policies
    ADD COLUMN IF NOT EXISTS step_up_window INTERVAL NOT NULL DEFAULT INTERVAL '5 minutes'
        CHECK (step_up_window BETWEEN INTERVAL '1 minute' AND INTERVAL '60 minutes'),
    ADD COLUMN IF NOT EXISTS step_up_methods TEXT[]
        CHECK (step_up_methods IS NULL OR (cardinality(step_up_methods) > 0
               AND step_up_methods <@ ARRAY['totp', 'recovery_code', 'otp', 'webauthn', 'push']::TEXT[]));

CREATE FUNCTION auth.clear_step_ups_on_password_change() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM auth.mfa_verifications WHERE user_id = NEW.user_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER clear_step_ups_on_password_change AFTER UPDATE OF password_hash ON auth.password_credentials
FOR EACH ROW WHEN (OLD.password_hash IS DISTINCT FROM NEW.password_hash)
EXECUTE FUNCTION auth.clear_step_ups_on_password_change();
