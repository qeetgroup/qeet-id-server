-- 0171_mfa_failure_streaks — wrong second factors in a row, over every window.
--
-- A sign-in's attempts were bounded only per ten minutes, so whoever held a
-- password could keep guessing codes at that rate for weeks. A person's wrong
-- answers in a row are now counted until one is right; at the limit their
-- second-factor sign-in locks until a password reset or an administrator's
-- reset of their factors.
CREATE TABLE auth.mfa_failure_streaks (
    user_id   UUID PRIMARY KEY REFERENCES "user".users(id) ON DELETE CASCADE,
    failures  INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0),
    locked_at TIMESTAMPTZ
);
