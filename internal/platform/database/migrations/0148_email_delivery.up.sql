-- 0148_email_delivery — what happened to each email, and who not to mail.
--
-- The senders sent and returned; nothing recorded a message, and bounces and
-- complaints reached nothing, so mail kept going to dead addresses (which is
-- what gets a sending domain blocked) and nobody could say whether an
-- invitation arrived. Addresses are kept as a SHA-256 of the lower-cased
-- address for lookups, plus a masked hint for people; never in plain text.

-- One row per email handed to a provider (or refused before it).
CREATE TABLE platform.email_messages (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    to_hash             TEXT NOT NULL,
    to_hint             TEXT NOT NULL,
    template            TEXT NOT NULL DEFAULT '',
    provider            TEXT NOT NULL,
    provider_message_id TEXT,
    status              TEXT NOT NULL CHECK (status IN ('sent', 'delivered', 'bounced', 'complained', 'suppressed', 'failed')),
    status_reason       TEXT NOT NULL DEFAULT '',
    sent_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX email_messages_tenant_to_idx ON platform.email_messages (tenant_id, to_hash, sent_at DESC);
CREATE UNIQUE INDEX email_messages_provider_id_idx ON platform.email_messages (provider, provider_message_id)
    WHERE provider_message_id IS NOT NULL;
CREATE INDEX email_messages_sent_at_idx ON platform.email_messages (sent_at);

-- An address no mail goes to: a hard bounce (it doesn't exist) or a complaint
-- (its owner marked our mail as spam). Both are facts about the address, so a
-- suppression holds platform-wide; tenant_id is the organisation whose mail
-- caused it, which alone may clear it.
CREATE TABLE platform.email_suppressions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID REFERENCES tenant.tenants(id) ON DELETE SET NULL,
    address_hash TEXT NOT NULL,
    address_hint TEXT NOT NULL,
    reason       TEXT NOT NULL CHECK (reason IN ('bounce', 'complaint')),
    detail       TEXT NOT NULL DEFAULT '',
    message_id   UUID REFERENCES platform.email_messages(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    cleared_at   TIMESTAMPTZ,
    cleared_by   UUID
);
CREATE UNIQUE INDEX email_suppressions_active_idx ON platform.email_suppressions (address_hash)
    WHERE cleared_at IS NULL;
CREATE INDEX email_suppressions_tenant_idx ON platform.email_suppressions (tenant_id, created_at DESC);
