-- 0120_session_switch — switching organisation replaces the session in use.
--
-- superseded_by: set on a session ended by switching organisation, to the
-- session that replaced it (the same sign-in, now scoped to another
-- organisation). The person's own session list leaves superseded sessions
-- out, so it shows one entry per sign-in however often they switch.
--
-- hook_claims: the claims the organisation's authentication hook added when
-- the session was opened (sign-in or switch), so every renewal issues them
-- again instead of dropping them after the first access token expires.
ALTER TABLE auth.sessions
    ADD COLUMN IF NOT EXISTS superseded_by UUID REFERENCES auth.sessions(id) ON DELETE SET NULL;
ALTER TABLE auth.sessions ADD COLUMN IF NOT EXISTS hook_claims JSONB;
