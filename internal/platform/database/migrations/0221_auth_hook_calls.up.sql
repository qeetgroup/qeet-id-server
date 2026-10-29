-- 0221_auth_hook_calls — how each sign-in hook has been answering: its last
-- call and outcome, and how many calls it has had, skipped and denied.
ALTER TABLE tenant.auth_hooks
    ADD COLUMN IF NOT EXISTS last_called_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_outcome TEXT,
    ADD COLUMN IF NOT EXISTS last_status_code INTEGER,
    ADD COLUMN IF NOT EXISTS call_count BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS skip_count BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS deny_count BIGINT NOT NULL DEFAULT 0;
