-- 0156_idempotency_keys — the answer to each request sent with an
-- Idempotency-Key, so a client that retries gets the same answer instead of
-- the action happening twice.
--
-- A row is claimed before the request runs and completed with its answer,
-- sealed, as some answers carry a secret shown once. Rows go after a day.
CREATE TABLE platform.idempotency_keys (
    scope        TEXT        NOT NULL,
    key          TEXT        NOT NULL,
    request_hash TEXT        NOT NULL,
    status       INT,
    content_type TEXT,
    body_enc     BYTEA,
    body_nonce   BYTEA,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (scope, key)
);

CREATE INDEX idx_idempotency_keys_created ON platform.idempotency_keys (created_at);
