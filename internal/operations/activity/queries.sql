-- Queries for the activity domain.
-- Static queries against audit.events; compiled by sqlc into ./dbgen.
-- All queries are scoped by tenant_id (multi-tenancy).

-- name: ListActivityHistory :many
-- Cursor-paginated history, newest first. Optional filters: action type array,
-- actor, subject (actor OR user-resource target), time range, and GIN full-text
-- search. The cursor carries both created_at and id so the tuple comparison can
-- be expanded — sqlc does not support row-value predicates, so
-- (created_at, id) < (cursor_ts, cursor_id) is rewritten as the equivalent OR
-- expression.
-- ip is nullable INET; COALESCE(host(ip), '')::text ensures a non-null string.
-- request_id is nullable TEXT (may be empty); it is surfaced so the console can
-- display, copy, and correlate events by request.
-- subject captures a user's full identity timeline: every event where that user
-- is either the actor or the target of a 'user' resource event.
-- actor_display_name / actor_email are LEFT-joined from the users table so the
-- console can show a human actor name instead of a bare UUID (nullable: system/
-- service actors have no user row).
SELECT e.id, e.actor_user_id, e.actor_type, e.action, e.resource_type, e.resource_id,
       COALESCE(host(e.ip), '')::text AS ip, e.user_agent, e.request_id, e.created_at, e.metadata, e.tenant_id,
       u.display_name AS actor_display_name, u.email AS actor_email
FROM audit.events e
LEFT JOIN "user".users u ON u.id = e.actor_user_id AND u.tenant_id = e.tenant_id
WHERE e.tenant_id = @tenant_id
  AND (sqlc.narg('actions')::text[] IS NULL OR e.action = ANY(sqlc.narg('actions')))
  AND (sqlc.narg('actor_id')::uuid IS NULL OR e.actor_user_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('subject')::uuid IS NULL OR e.actor_user_id = sqlc.narg('subject') OR (e.resource_type = 'user' AND e.resource_id = sqlc.narg('subject')))
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR e.created_at >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR e.created_at <= sqlc.narg('to_ts'))
  AND (sqlc.narg('q')::text IS NULL OR e.search_vector @@ websearch_to_tsquery('simple', sqlc.narg('q')))
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL OR e.created_at < sqlc.narg('cursor_ts') OR (e.created_at = sqlc.narg('cursor_ts') AND e.id < sqlc.narg('cursor_id')::uuid))
ORDER BY e.created_at DESC, e.id DESC
LIMIT @row_limit;

-- name: ReplayActivityHistory :many
-- Replay events newer than (after_ts, after_id) in chronological order (ASC).
-- Used by the SSE handler to replay missed events on reconnect. The tuple
-- comparison (created_at, id) > (after_ts, after_id) is expanded — the #1
-- sqlc gotcha with row-value predicates.
SELECT e.id, e.actor_user_id, e.actor_type, e.action, e.resource_type, e.resource_id,
       COALESCE(host(e.ip), '')::text AS ip, e.user_agent, e.request_id, e.created_at, e.metadata, e.tenant_id,
       u.display_name AS actor_display_name, u.email AS actor_email
FROM audit.events e
LEFT JOIN "user".users u ON u.id = e.actor_user_id AND u.tenant_id = e.tenant_id
WHERE e.tenant_id = @tenant_id
  AND (e.created_at > @after_ts OR (e.created_at = @after_ts AND e.id > @after_id))
ORDER BY e.created_at ASC, e.id ASC
LIMIT 100;

-- name: SummarizeActivityByAction :many
-- Per-action counts over the same predicates as ListActivityHistory (no cursor/
-- limit). Folded into severity/category/outcome buckets in Go via severityOf()/
-- categoryOf()/outcomeOf() — those are derived from `action`, not stored columns,
-- so aggregation by severity cannot be a plain GROUP BY on a column.
SELECT action, count(*)::bigint AS count
FROM audit.events
WHERE tenant_id = @tenant_id
  AND (sqlc.narg('actions')::text[] IS NULL OR action = ANY(sqlc.narg('actions')))
  AND (sqlc.narg('actor_id')::uuid IS NULL OR actor_user_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('subject')::uuid IS NULL OR actor_user_id = sqlc.narg('subject') OR (resource_type = 'user' AND resource_id = sqlc.narg('subject')))
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR created_at <= sqlc.narg('to_ts'))
  AND (sqlc.narg('q')::text IS NULL OR search_vector @@ websearch_to_tsquery('simple', sqlc.narg('q')))
GROUP BY action;

-- name: SummarizeActivityTotals :one
-- Total events and unique-actor count over the same window. unique_actors cannot
-- be folded from the per-action rows (one actor spans many actions), so it needs
-- its own aggregate pass.
SELECT count(*)::bigint AS total,
       count(DISTINCT actor_user_id)::bigint AS unique_actors
FROM audit.events
WHERE tenant_id = @tenant_id
  AND (sqlc.narg('actions')::text[] IS NULL OR action = ANY(sqlc.narg('actions')))
  AND (sqlc.narg('actor_id')::uuid IS NULL OR actor_user_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('subject')::uuid IS NULL OR actor_user_id = sqlc.narg('subject') OR (resource_type = 'user' AND resource_id = sqlc.narg('subject')))
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR created_at <= sqlc.narg('to_ts'))
  AND (sqlc.narg('q')::text IS NULL OR search_vector @@ websearch_to_tsquery('simple', sqlc.narg('q')));

-- name: SummarizeActivityTimeSeries :many
-- Per-bucket, per-action counts for sparklines. Bucket width = @bucket_seconds.
-- Grouped by action too so the handler can fold each bucket into per-outcome
-- series (severity/outcome are derived from action in Go, not columns). Empty
-- buckets are omitted (the frontend fills gaps). Same predicates as history.
SELECT (to_timestamp(floor(extract(epoch FROM created_at) / @bucket_seconds::bigint) * @bucket_seconds::bigint))::timestamptz AS bucket,
       action,
       count(*)::bigint AS count
FROM audit.events
WHERE tenant_id = @tenant_id
  AND (sqlc.narg('actions')::text[] IS NULL OR action = ANY(sqlc.narg('actions')))
  AND (sqlc.narg('actor_id')::uuid IS NULL OR actor_user_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('subject')::uuid IS NULL OR actor_user_id = sqlc.narg('subject') OR (resource_type = 'user' AND resource_id = sqlc.narg('subject')))
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR created_at <= sqlc.narg('to_ts'))
  AND (sqlc.narg('q')::text IS NULL OR search_vector @@ websearch_to_tsquery('simple', sqlc.narg('q')))
GROUP BY bucket, action
ORDER BY bucket ASC;

-- name: GetActivityEventByID :one
-- Anchor lookup for related-events correlation, tenant-scoped. Returns
-- pgx.ErrNoRows when the id is unknown OR belongs to another tenant, so a
-- cross-tenant fetch surfaces as 404 (never a leak).
SELECT e.id, e.actor_user_id, e.actor_type, e.action, e.resource_type, e.resource_id,
       COALESCE(host(e.ip), '')::text AS ip, e.user_agent, e.request_id, e.created_at, e.metadata, e.tenant_id,
       u.display_name AS actor_display_name, u.email AS actor_email
FROM audit.events e
LEFT JOIN "user".users u ON u.id = e.actor_user_id AND u.tenant_id = e.tenant_id
WHERE e.tenant_id = @tenant_id AND e.id = @id;

-- name: ListRelatedByRequestID :many
-- Other events sharing the anchor's request_id. Caller only runs this when the
-- anchor's request_id is non-empty.
SELECT e.id, e.actor_user_id, e.actor_type, e.action, e.resource_type, e.resource_id,
       COALESCE(host(e.ip), '')::text AS ip, e.user_agent, e.request_id, e.created_at, e.metadata, e.tenant_id,
       u.display_name AS actor_display_name, u.email AS actor_email
FROM audit.events e
LEFT JOIN "user".users u ON u.id = e.actor_user_id AND u.tenant_id = e.tenant_id
WHERE e.tenant_id = @tenant_id
  AND e.request_id = @request_id
  AND e.id <> @exclude_id
ORDER BY e.created_at ASC, e.id ASC
LIMIT @row_limit;

-- name: ListRelatedByActor :many
-- Same actor within [@from_ts, @to_ts] (a symmetric window around the anchor),
-- excluding the anchor. Ordered newest-first for parity with history.
SELECT e.id, e.actor_user_id, e.actor_type, e.action, e.resource_type, e.resource_id,
       COALESCE(host(e.ip), '')::text AS ip, e.user_agent, e.request_id, e.created_at, e.metadata, e.tenant_id,
       u.display_name AS actor_display_name, u.email AS actor_email
FROM audit.events e
LEFT JOIN "user".users u ON u.id = e.actor_user_id AND u.tenant_id = e.tenant_id
WHERE e.tenant_id = @tenant_id
  AND e.actor_user_id = @actor_id
  AND e.created_at BETWEEN @from_ts AND @to_ts
  AND e.id <> @exclude_id
ORDER BY e.created_at DESC, e.id DESC
LIMIT @row_limit;
