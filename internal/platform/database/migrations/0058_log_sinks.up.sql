-- 0058_log_sinks — per-tenant SIEM/log-streaming sinks (Splunk HEC / Datadog / generic HTTP); a forwarder streams new audit.events past each sink's cursor. token is write-only.
CREATE TABLE tenant.log_sinks (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    type               TEXT NOT NULL,            -- splunk_hec | datadog | http
    endpoint           TEXT NOT NULL,
    token              TEXT NOT NULL DEFAULT '', -- HEC token / DD-API-KEY / Bearer
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    -- High-watermark cursor over audit.events (created_at, id), advanced on a
    -- successful forward. NULL = forward from now on (don't backfill history).
    cursor_created_at  TIMESTAMPTZ,
    cursor_id          UUID,
    last_forwarded_at  TIMESTAMPTZ,
    last_error         TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_log_sinks_enabled ON tenant.log_sinks (enabled) WHERE enabled;



