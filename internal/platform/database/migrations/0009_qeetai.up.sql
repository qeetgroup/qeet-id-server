-- 0009_qeetai — Qeet AI: provider settings, conversations and usage.
--
-- Each table is headed by the package that owns it. A column marked (0010) is a
-- foreign key into another schema, which 0010_cross_schema_keys adds.

-- internal/operations/qeetai
-- tenant_id's key doesn't cascade: the organisation purge deletes the
-- conversations in batches first.
CREATE TABLE qeetai.conversations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL, -- tenant.tenants (0010)
    user_id    UUID NOT NULL,
    title      TEXT NOT NULL DEFAULT 'New conversation',
    pinned     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, id)
);
CREATE INDEX conversations_tenant_id_user_id_pinned_updated_at_idx
    ON qeetai.conversations (tenant_id, user_id, pinned DESC, updated_at DESC);

-- internal/operations/qeetai
-- tenant_id is the conversation's: the key to (tenant_id, id) holds it there.
CREATE TABLE qeetai.conversation_turns (
    conversation_id UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT conversation_turns_conversation_id_fkey FOREIGN KEY (tenant_id, conversation_id)
        REFERENCES qeetai.conversations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX conversation_turns_tenant_id_idx ON qeetai.conversation_turns (tenant_id);

-- internal/operations/qeetai
-- tenant_id is the conversation's: the key to (tenant_id, id) holds it there.
CREATE TABLE qeetai.messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    conversation_id UUID NOT NULL,
    role            TEXT NOT NULL,
    content         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT messages_conversation_id_fkey FOREIGN KEY (tenant_id, conversation_id)
        REFERENCES qeetai.conversations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT messages_role_check CHECK (role IN ('user', 'assistant', 'tool'))
);
CREATE INDEX messages_conversation_id_created_at_idx ON qeetai.messages (conversation_id, created_at);
CREATE INDEX messages_tenant_id_idx ON qeetai.messages (tenant_id);

-- internal/operations/qeetai
CREATE TABLE qeetai.provider_settings (
    tenant_id      UUID PRIMARY KEY, -- tenant.tenants (0010)
    provider       TEXT NOT NULL,
    model          TEXT NOT NULL,
    base_url       TEXT NOT NULL DEFAULT '',
    max_tokens     INTEGER NOT NULL DEFAULT 4096,
    key_ciphertext BYTEA NOT NULL,
    key_nonce      BYTEA NOT NULL,
    key_last4      TEXT NOT NULL DEFAULT '',
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT provider_settings_max_tokens_check CHECK (max_tokens > 0 AND max_tokens <= 200000),
    CONSTRAINT provider_settings_provider_check CHECK (provider IN ('anthropic', 'openai', 'azure'))
);

-- internal/operations/qeetai
CREATE TABLE qeetai.settings (
    tenant_id                   UUID PRIMARY KEY, -- tenant.tenants (0010)
    conversation_retention_days INTEGER,
    updated_by                  UUID,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT settings_conversation_retention_days_check CHECK (
        conversation_retention_days >= 1
        AND conversation_retention_days <= 3650)
);

-- internal/operations/qeetai
CREATE TABLE qeetai.usage (
    tenant_id     UUID NOT NULL, -- tenant.tenants (0010)
    month         DATE NOT NULL,
    messages      INTEGER NOT NULL DEFAULT 0,
    input_tokens  BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    last_used_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, month)
);
