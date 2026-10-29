ALTER TABLE auth.bot_events DROP COLUMN IF EXISTS user_id;
ALTER TABLE auth.security_events DROP COLUMN IF EXISTS resolved_by;
