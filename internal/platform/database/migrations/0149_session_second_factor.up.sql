-- 0149_session_second_factor — whether, and how, the sign-in behind a session
-- met a second factor (QTID-800).
--
-- An organisation's MFA requirement was read only for the account's own
-- organisation, at sign-in. A session or code issued for another organisation
-- (switching into it, accepting its invitation, signing in to one of its
-- applications) never asked whether that organisation's requirement was met,
-- because nothing recorded whether the sign-in had met a factor. These columns
-- do: NULL is none (or not known, for sessions opened before this migration),
-- otherwise how it was met:
--   mfa             the sign-in met a second-factor challenge
--   passkey         the sign-in was a passkey (a factor by itself)
--   trusted_device  a remembered device stood in for the factor, as the
--                   organisation allows at sign-in
--   step_up         a fresh step-up of the session switched from
ALTER TABLE auth.sessions
    ADD COLUMN IF NOT EXISTS second_factor TEXT
        CHECK (second_factor IN ('mfa', 'passkey', 'trusted_device', 'step_up'));
ALTER TABLE auth.login_sessions
    ADD COLUMN IF NOT EXISTS second_factor TEXT
        CHECK (second_factor IN ('mfa', 'passkey', 'trusted_device', 'step_up'));
