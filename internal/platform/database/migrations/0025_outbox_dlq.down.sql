DROP INDEX IF EXISTS platform.idx_outbox_retry_eligible;
DROP INDEX IF EXISTS platform.idx_outbox_dlq_dead_lettered_at;
DROP TABLE IF EXISTS platform.outbox_dead_letter;

ALTER TABLE platform.outbox
    DROP COLUMN IF EXISTS last_attempt_at,
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS attempts;
