-- 0219_qeetai_usage_retention — what each organisation's Qeet AI used, month by
-- month, and how long it keeps its conversations.
CREATE TABLE qeetai.usage (
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    month         DATE NOT NULL,
    messages      INTEGER NOT NULL DEFAULT 0,
    input_tokens  BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    last_used_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, month)
);

ALTER TABLE qeetai.usage ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON qeetai.usage
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

-- conversation_retention_days: a conversation untouched that long is deleted
-- with its messages; NULL keeps them.
CREATE TABLE qeetai.settings (
    tenant_id                   UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    conversation_retention_days INTEGER CHECK (conversation_retention_days BETWEEN 1 AND 3650),
    updated_by                  UUID,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE qeetai.settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON qeetai.settings
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
