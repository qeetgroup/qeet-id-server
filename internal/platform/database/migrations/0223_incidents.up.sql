-- 0223_incidents — service incidents, posted by an operator and shown to every
-- organisation beside the state of each part of the service.
CREATE TABLE platform.incidents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component   TEXT NOT NULL CHECK (component IN ('api', 'sign_in', 'email', 'webhooks', 'directory')),
    impact      TEXT NOT NULL CHECK (impact IN ('maintenance', 'degraded', 'outage')),
    title       TEXT NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    detail      TEXT NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);
CREATE INDEX incidents_started_idx ON platform.incidents (started_at DESC);
