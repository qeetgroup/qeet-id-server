-- 0125_session_limit — an organisation may cap a person's simultaneous
-- sessions.
--
-- max_sessions: how many live sessions one person may hold in the
-- organisation at once; NULL = no limit (the default, as before).
-- session_limit_action: what a sign-in at the limit does — 'evict_oldest'
-- ends the person's least recently used session, 'refuse' refuses the new
-- sign-in. An ended session's renewal stops at once; an access token it
-- already issued lasts out its own short lifetime.
ALTER TABLE tenant.security_policies
    ADD COLUMN IF NOT EXISTS max_sessions INT CHECK (max_sessions BETWEEN 1 AND 1000),
    ADD COLUMN IF NOT EXISTS session_limit_action TEXT NOT NULL DEFAULT 'evict_oldest'
        CHECK (session_limit_action IN ('evict_oldest', 'refuse'));
