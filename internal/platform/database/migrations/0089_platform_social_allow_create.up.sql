-- Carry the ceremony intent through the OAuth redirect: sign-up may create a new
-- account just-in-time, but sign-in must only authenticate an existing one (no
-- silent account creation). Defaults false = secure (login-only) when unset.
ALTER TABLE auth.platform_social_states
    ADD COLUMN allow_create boolean NOT NULL DEFAULT false;
