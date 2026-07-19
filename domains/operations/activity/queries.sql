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
-- subject captures a user's full identity timeline: every event where that user
-- is either the actor or the target of a 'user' resource event.
SELECT id, actor_user_id, actor_type, action, resource_type, resource_id,
       COALESCE(host(ip), '')::text AS ip, user_agent, created_at, metadata, tenant_id
FROM audit.events
WHERE tenant_id = @tenant_id
  AND (sqlc.narg('actions')::text[] IS NULL OR action = ANY(sqlc.narg('actions')))
  AND (sqlc.narg('actor_id')::uuid IS NULL OR actor_user_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('subject')::uuid IS NULL OR actor_user_id = sqlc.narg('subject') OR (resource_type = 'user' AND resource_id = sqlc.narg('subject')))
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR created_at <= sqlc.narg('to_ts'))
  AND (sqlc.narg('q')::text IS NULL OR search_vector @@ websearch_to_tsquery('simple', sqlc.narg('q')))
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL OR created_at < sqlc.narg('cursor_ts') OR (created_at = sqlc.narg('cursor_ts') AND id < sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT @row_limit;

-- name: ReplayActivityHistory :many
-- Replay events newer than (after_ts, after_id) in chronological order (ASC).
-- Used by the SSE handler to replay missed events on reconnect. The tuple
-- comparison (created_at, id) > (after_ts, after_id) is expanded — the #1
-- sqlc gotcha with row-value predicates.
SELECT id, actor_user_id, actor_type, action, resource_type, resource_id,
       COALESCE(host(ip), '')::text AS ip, user_agent, created_at, metadata, tenant_id
FROM audit.events
WHERE tenant_id = @tenant_id
  AND (created_at > @after_ts OR (created_at = @after_ts AND id > @after_id))
ORDER BY created_at ASC, id ASC
LIMIT 100;
