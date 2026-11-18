-- Queries for the siem domain.
-- Static queries against organization.log_sinks and audit.events live here and are
-- compiled by sqlc into ./dbgen.
-- name: ListLogSinks :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, type, endpoint, enabled, last_forwarded_at, last_error, created_at
FROM organization.log_sinks
WHERE organization_id = @organization_id
ORDER BY created_at DESC
LIMIT 1001;

-- name: SetLogSinkEnabled :execrows
UPDATE organization.log_sinks
SET enabled = @enabled
WHERE id = @id AND organization_id = @organization_id;

-- name: DeleteLogSink :execrows
DELETE FROM organization.log_sinks
WHERE id = @id AND organization_id = @organization_id;

-- Advance the high-watermark cursor after a successful forward.
-- name: AdvanceLogSinkCursor :exec
UPDATE organization.log_sinks
SET cursor_created_at = @cursor_created_at,
    cursor_id         = @cursor_id,
    last_forwarded_at = NOW(),
    last_error        = '',
    failures          = 0,
    next_attempt_at   = NULL
WHERE id = @id;

-- Record a delivery error on a sink without advancing its cursor, and put
-- its next attempt off: twice as long after each failure in a row, from 10
-- seconds up to an hour.
-- name: SetLogSinkError :exec
UPDATE organization.log_sinks
SET last_error      = @last_error,
    failures        = failures + 1,
    next_attempt_at = NOW() + LEAST(INTERVAL '1 hour', INTERVAL '10 seconds' * power(2, LEAST(failures, 12)))
WHERE id = @id;

-- ClaimLogSink leases an enabled sink due an attempt to this instance until
-- @leased_until, and returns its cursor. No row: another instance holds it,
-- or it is backing off.
-- name: ClaimLogSink :one
UPDATE organization.log_sinks
SET leased_until = @leased_until::timestamptz
WHERE id = @id AND enabled
  AND (leased_until IS NULL OR leased_until < NOW())
  AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
RETURNING cursor_created_at, cursor_id;

-- ReleaseLogSink ends this instance's lease on a sink.
-- name: ReleaseLogSink :exec
UPDATE organization.log_sinks SET leased_until = NULL WHERE id = @id;

-- Fetch audit events strictly after (after_at, after_id) for an organization.
-- Row-value comparison (created_at, id) > (after_at, after_id) is rewritten
-- as an equivalent OR expression — the #1 sqlc gotcha with tuple predicates.
-- ip is nullable INET; COALESCE(host(ip), '') prevents a NULL-into-string scan
-- error. The mapping layer converts '' back to nil for the AuditEvent.IP field.
-- name: FetchAuditEventsAfterCursor :many
SELECT id, organization_id, actor_user_id, actor_type, action, resource_type,
       resource_id, COALESCE(host(ip), '')::text AS host, request_id, created_at,
       user_agent, metadata
FROM audit.events
WHERE organization_id = @organization_id
  AND (created_at > @after_at OR (created_at = @after_at AND id > @after_id))
ORDER BY created_at ASC, id ASC
LIMIT @row_limit;

-- name: InsertLogSink :one
-- A new destination starts from now: the nil cursor id sorts before every
-- event of its first second.
INSERT INTO organization.log_sinks
    (id, organization_id, type, endpoint, token_ct, token_nonce, cursor_created_at, cursor_id)
VALUES (@id, @organization_id, @type, @endpoint, @token_ct, @token_nonce, NOW(), '00000000-0000-0000-0000-000000000000')
RETURNING id, type, endpoint, enabled, last_forwarded_at, last_error, created_at;

-- name: ListEnabledLogSinks :many
-- Every organization's enabled destinations, for the forwarding job.
SELECT id, organization_id, type, endpoint, token_ct, token_nonce
FROM organization.log_sinks
WHERE enabled;

-- name: GetLogSinkSecret :one
SELECT id, organization_id, type, endpoint, token_ct, token_nonce
FROM organization.log_sinks WHERE id = @id AND organization_id = @organization_id;
