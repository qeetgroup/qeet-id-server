-- IMPROVEMENTS §6.2: outbox dispatcher needs a bounded retry window
-- with visibility into permanently-failing events. Today a bad event
-- stays in platform.outbox forever, re-tried every dispatcher tick.
--
-- Schema additions:
--   * attempts          — how many times the dispatcher has tried.
--   * last_error        — error message from the most recent attempt.
--   * last_attempt_at   — when the most recent attempt finished.
-- These let us implement exponential backoff between retries.
--
-- platform.outbox_dead_letter is the holding pen: rows that exceed
-- MAX_ATTEMPTS are moved here so the live queue stays clean. Ops can
-- inspect via GET /v1/admin/outbox/dlq and decide to replay or purge.

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
