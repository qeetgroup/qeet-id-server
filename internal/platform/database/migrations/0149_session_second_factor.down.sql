ALTER TABLE auth.login_sessions DROP COLUMN IF EXISTS second_factor;
ALTER TABLE auth.sessions DROP COLUMN IF EXISTS second_factor;
