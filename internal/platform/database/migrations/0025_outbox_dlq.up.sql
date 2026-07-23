-- 0025_outbox_dlq — bounded retry + dead-letter for the outbox dispatcher.
-- attempts/last_error/last_attempt_at drive exponential backoff; rows past MAX_ATTEMPTS
-- move to outbox_dead_letter (inspect/replay via /v1/admin/outbox/dlq) so the live queue stays clean.

ALTER TABLE platform.outbox
    ADD COLUMN IF NOT EXISTS attempts        INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_error      TEXT,
    ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS platform.outbox_dead_letter (
    id              UUID PRIMARY KEY,
    aggregate_id    UUID NOT NULL,
    topic           TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    attempts        INT NOT NULL,
    last_error      TEXT,
    dead_lettered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_outbox_dlq_dead_lettered_at
    ON platform.outbox_dead_letter (dead_lettered_at DESC);

-- Help the dispatcher's "next batch" picker skip rows in backoff.
CREATE INDEX IF NOT EXISTS idx_outbox_retry_eligible
    ON platform.outbox (last_attempt_at NULLS FIRST)
    WHERE published_at IS NULL;
