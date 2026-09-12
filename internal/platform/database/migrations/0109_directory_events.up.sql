CREATE TABLE tenant.directory_events (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    connection_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    trigger_type TEXT NOT NULL CHECK (trigger_type IN ('push', 'manual', 'sign-in')),
    resource_type TEXT NOT NULL CHECK (resource_type IN ('user', 'group', 'connection')),
    resource_id TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL,
    duration_ms BIGINT NOT NULL CHECK (duration_ms >= 0),
    http_status INTEGER NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    status TEXT NOT NULL CHECK (status IN ('success', 'warning', 'failed')),
    users_synced INTEGER NOT NULL DEFAULT 0 CHECK (users_synced >= 0),
    groups_synced INTEGER NOT NULL DEFAULT 0 CHECK (groups_synced >= 0),
    error_code TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '' CHECK (severity IN ('', 'warning', 'critical')),
    resolution TEXT NOT NULL DEFAULT 'open' CHECK (resolution IN ('open', 'resolved', 'retried')),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES "user".users(id) ON DELETE SET NULL,
    retry_of UUID REFERENCES tenant.directory_events(id) ON DELETE SET NULL,
    UNIQUE (tenant_id, id)
);

CREATE INDEX directory_events_tenant_started ON tenant.directory_events(tenant_id, started_at DESC, id DESC);
CREATE INDEX directory_events_connection_started ON tenant.directory_events(tenant_id, connection_id, started_at DESC);
CREATE INDEX directory_events_open_errors ON tenant.directory_events(tenant_id, started_at DESC) WHERE status <> 'success' AND resolution = 'open';

CREATE TABLE tenant.directory_alerts (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    connection_id TEXT,
    threshold INTEGER NOT NULL DEFAULT 1 CHECK (threshold BETWEEN 1 AND 100),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_notified_at TIMESTAMPTZ
);

CREATE INDEX directory_alerts_tenant ON tenant.directory_alerts(tenant_id, user_id);
