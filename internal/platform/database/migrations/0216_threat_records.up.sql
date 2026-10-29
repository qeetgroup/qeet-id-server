-- 0216_threat_records — who resolved an anomaly, and which account a bot
-- detection's sign-in attempt was for.
ALTER TABLE auth.security_events ADD COLUMN IF NOT EXISTS resolved_by UUID;
ALTER TABLE auth.bot_events ADD COLUMN IF NOT EXISTS user_id UUID;
