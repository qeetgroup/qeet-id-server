-- Queries for the siem domain.
-- Static queries against tenant.log_sinks and audit.events live here and are
-- compiled by sqlc into ./dbgen.
-- The token field is write-only: included in INSERTs and internal reads but
-- never projected to the API.

-- name: InsertLogSink :one
INSERT INTO tenant.log_sinks (tenant_id, type, endpoint, token, cursor_created_at, cursor_id)
VALUES (@tenant_id, @type, @endpoint, @token, NOW(), '00000000-0000-0000-0000-000000000000')
RETURNING id, type, endpoint, enabled, last_forwarded_at, last_error, created_at;

-- name: ListLogSinks :many
SELECT id, type, endpoint, enabled, last_forwarded_at, last_error, created_at
FROM tenant.log_sinks
WHERE tenant_id = @tenant_id
ORDER BY created_at DESC;

-- name: SetLogSinkEnabled :execrows
UPDATE tenant.log_sinks
SET enabled = @enabled
WHERE id = @id AND tenant_id = @tenant_id;

-- name: DeleteLogSink :execrows
DELETE FROM tenant.log_sinks
WHERE id = @id AND tenant_id = @tenant_id;

-- Advance the high-watermark cursor after a successful forward.
-- name: AdvanceLogSinkCursor :exec
UPDATE tenant.log_sinks
SET cursor_created_at = @cursor_created_at,
    cursor_id         = @cursor_id,
    last_forwarded_at = NOW(),
    last_error        = ''
WHERE id = @id;

-- Record a delivery error on a sink without advancing its cursor.
-- name: SetLogSinkError :exec
UPDATE tenant.log_sinks
SET last_error = @last_error
WHERE id = @id;

-- Load all enabled sinks with their cursors for the background forwarder.
-- Nullable cursor columns are read as-is; Go maps nil → sensible defaults.
-- name: ListEnabledLogSinks :many
SELECT id, tenant_id, type, endpoint, token, cursor_created_at, cursor_id
FROM tenant.log_sinks
WHERE enabled;

-- Fetch audit events strictly after (after_at, after_id) for a tenant.
-- Row-value comparison (created_at, id) > (after_at, after_id) is rewritten
-- as an equivalent OR expression — the #1 sqlc gotcha with tuple predicates.
-- ip is nullable INET; COALESCE(host(ip), '') prevents a NULL-into-string scan
-- error. The mapping layer converts '' back to nil for the AuditEvent.IP field.
-- name: FetchAuditEventsAfterCursor :many
SELECT id, tenant_id, actor_user_id, actor_type, action, resource_type,
       resource_id, COALESCE(host(ip), '')::text AS host, request_id, created_at
FROM audit.events
WHERE tenant_id = @tenant_id
  AND (created_at > @after_at OR (created_at = @after_at AND id > @after_id))
ORDER BY created_at ASC, id ASC
LIMIT @row_limit;
