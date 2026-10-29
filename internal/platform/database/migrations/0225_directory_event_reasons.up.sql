-- 0225_directory_event_reasons — why a directory operation failed, in its own
-- code with safe details such as the directory's host, and whom a sign-in was
-- for: the login name tried and, once known, the person.
ALTER TABLE tenant.directory_events
    ADD COLUMN IF NOT EXISTS reason  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS params  JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS subject TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS user_id UUID;
