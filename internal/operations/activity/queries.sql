-- Queries for the activity domain.
-- Static queries against audit.events; compiled by sqlc into ./dbgen.
-- All queries are scoped by organization_id (multi-tenancy).

-- name: ListActivityHistory :many
-- Cursor-paginated history, newest first. Optional filters: action type array,
-- actor, subject (actor, user-resource target or metadata.user_id), time range,
-- full-text search (audit.search_query: words, as prefixes, or the actor's name or email), resource types, a resource, an address, and the
-- categories and severities activity gives an action (audit.activity_category
-- and audit.activity_severity), either a set of severities or, with
-- min_severity, at least one. The cursor carries both created_at and id so the
-- tuple comparison can be expanded — sqlc does not support row-value
-- predicates, so (created_at, id) < (cursor_ts, cursor_id) is rewritten as the
-- equivalent OR expression.
-- ip is nullable INET; COALESCE(host(ip), '')::text ensures a non-null string.
-- request_id is nullable TEXT (may be empty); it is surfaced so the console can
-- display, copy, and correlate events by request.
-- subject captures a user's full identity timeline: every event where that user
-- is the actor, the target of a 'user' resource event, or the person another
-- resource's event names in metadata.user_id (a group membership change).
-- actor_display_name / actor_email are LEFT-joined from the users table so the
-- console can show a human actor name instead of a bare UUID (nullable: system/
-- service actors have no user row).
SELECT e.id, e.actor_user_id, e.actor_type, e.action, e.resource_type, e.resource_id,
       COALESCE(host(e.ip), '')::text AS ip, e.user_agent, e.request_id, e.created_at, e.metadata, e.organization_id,
       u.display_name AS actor_display_name, u.email AS actor_email
FROM audit.events e
LEFT JOIN account.users u ON u.id = e.actor_user_id AND u.organization_id = e.organization_id
WHERE e.organization_id = @organization_id
  AND (sqlc.narg('actions')::text[] IS NULL OR e.action = ANY(sqlc.narg('actions')))
  AND (sqlc.narg('actor_id')::uuid IS NULL OR e.actor_user_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('subject')::uuid IS NULL OR e.actor_user_id = sqlc.narg('subject') OR (e.resource_type = 'user' AND e.resource_id = sqlc.narg('subject')) OR e.metadata->>'user_id' = sqlc.narg('subject')::uuid::text)
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR e.created_at >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR e.created_at <= sqlc.narg('to_ts'))
  AND (sqlc.narg('q')::text IS NULL OR e.search_vector @@ audit.search_query(sqlc.narg('q'))
       OR e.actor_user_id IN (SELECT su.id FROM account.users su
           WHERE (su.email ILIKE sqlc.narg('q_like')::text || '%' OR su.display_name ILIKE '%' || sqlc.narg('q_like')::text || '%')
             AND (su.organization_id = @organization_id OR su.id IN (SELECT sr.user_id FROM rbac.user_roles sr WHERE sr.organization_id = @organization_id))))
  AND (sqlc.narg('resource_types')::text[] IS NULL OR e.resource_type = ANY(sqlc.narg('resource_types')))
  AND (sqlc.narg('resource_id')::uuid IS NULL OR e.resource_id = sqlc.narg('resource_id'))
  AND (sqlc.narg('ip')::inet IS NULL OR e.ip = sqlc.narg('ip'))
  AND (sqlc.narg('categories')::text[] IS NULL OR audit.activity_category(e.action) = ANY(sqlc.narg('categories')))
  AND (sqlc.narg('severities')::text[] IS NULL OR audit.activity_severity(e.action) = ANY(sqlc.narg('severities')))
  AND (sqlc.narg('min_severity')::text IS NULL
       OR array_position(ARRAY['info', 'success', 'warning', 'error', 'critical'], audit.activity_severity(e.action))
          >= array_position(ARRAY['info', 'success', 'warning', 'error', 'critical'], sqlc.narg('min_severity')::text))
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL OR e.created_at < sqlc.narg('cursor_ts') OR (e.created_at = sqlc.narg('cursor_ts') AND e.id < sqlc.narg('cursor_id')::uuid))
ORDER BY e.created_at DESC, e.id DESC
LIMIT @row_limit;

-- name: CountActivityHistory :one
-- How many events ListActivityHistory's filters match, counted up to
-- count_cap: a count of an organization's whole history would read all of it.
SELECT count(*)::bigint FROM (
    SELECT 1 FROM audit.events e
    WHERE e.organization_id = @organization_id
      AND (sqlc.narg('actions')::text[] IS NULL OR e.action = ANY(sqlc.narg('actions')))
      AND (sqlc.narg('actor_id')::uuid IS NULL OR e.actor_user_id = sqlc.narg('actor_id'))
      AND (sqlc.narg('subject')::uuid IS NULL OR e.actor_user_id = sqlc.narg('subject') OR (e.resource_type = 'user' AND e.resource_id = sqlc.narg('subject')) OR e.metadata->>'user_id' = sqlc.narg('subject')::uuid::text)
      AND (sqlc.narg('from_ts')::timestamptz IS NULL OR e.created_at >= sqlc.narg('from_ts'))
      AND (sqlc.narg('to_ts')::timestamptz IS NULL OR e.created_at <= sqlc.narg('to_ts'))
      AND (sqlc.narg('q')::text IS NULL OR e.search_vector @@ audit.search_query(sqlc.narg('q'))
       OR e.actor_user_id IN (SELECT su.id FROM account.users su
           WHERE (su.email ILIKE sqlc.narg('q_like')::text || '%' OR su.display_name ILIKE '%' || sqlc.narg('q_like')::text || '%')
             AND (su.organization_id = @organization_id OR su.id IN (SELECT sr.user_id FROM rbac.user_roles sr WHERE sr.organization_id = @organization_id))))
      AND (sqlc.narg('resource_types')::text[] IS NULL OR e.resource_type = ANY(sqlc.narg('resource_types')))
      AND (sqlc.narg('resource_id')::uuid IS NULL OR e.resource_id = sqlc.narg('resource_id'))
      AND (sqlc.narg('ip')::inet IS NULL OR e.ip = sqlc.narg('ip'))
      AND (sqlc.narg('categories')::text[] IS NULL OR audit.activity_category(e.action) = ANY(sqlc.narg('categories')))
      AND (sqlc.narg('severities')::text[] IS NULL OR audit.activity_severity(e.action) = ANY(sqlc.narg('severities')))
      AND (sqlc.narg('min_severity')::text IS NULL
           OR array_position(ARRAY['info', 'success', 'warning', 'error', 'critical'], audit.activity_severity(e.action))
              >= array_position(ARRAY['info', 'success', 'warning', 'error', 'critical'], sqlc.narg('min_severity')::text))
    LIMIT @count_cap
) matched;

-- name: ReplayActivityHistory :many
-- Replay events newer than (after_ts, after_id) in chronological order (ASC).
-- Used by the SSE handler to replay missed events on reconnect. The tuple
-- comparison (created_at, id) > (after_ts, after_id) is expanded — the #1
-- sqlc gotcha with row-value predicates.
SELECT e.id, e.actor_user_id, e.actor_type, e.action, e.resource_type, e.resource_id,
       COALESCE(host(e.ip), '')::text AS ip, e.user_agent, e.request_id, e.created_at, e.metadata, e.organization_id,
       u.display_name AS actor_display_name, u.email AS actor_email
FROM audit.events e
LEFT JOIN account.users u ON u.id = e.actor_user_id AND u.organization_id = e.organization_id
WHERE e.organization_id = @organization_id
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
WHERE audit.events.organization_id = @organization_id
  AND (sqlc.narg('actions')::text[] IS NULL OR action = ANY(sqlc.narg('actions')))
  AND (sqlc.narg('actor_id')::uuid IS NULL OR actor_user_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('subject')::uuid IS NULL OR actor_user_id = sqlc.narg('subject') OR (resource_type = 'user' AND resource_id = sqlc.narg('subject')) OR metadata->>'user_id' = sqlc.narg('subject')::uuid::text)
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR created_at <= sqlc.narg('to_ts'))
  AND (sqlc.narg('q')::text IS NULL OR search_vector @@ audit.search_query(sqlc.narg('q'))
       OR actor_user_id IN (SELECT su.id FROM account.users su
           WHERE (su.email ILIKE sqlc.narg('q_like')::text || '%' OR su.display_name ILIKE '%' || sqlc.narg('q_like')::text || '%')
             AND (su.organization_id = @organization_id OR su.id IN (SELECT sr.user_id FROM rbac.user_roles sr WHERE sr.organization_id = @organization_id))))
  AND (sqlc.narg('resource_types')::text[] IS NULL OR resource_type = ANY(sqlc.narg('resource_types')))
  AND (sqlc.narg('resource_id')::uuid IS NULL OR resource_id = sqlc.narg('resource_id'))
  AND (sqlc.narg('ip')::inet IS NULL OR ip = sqlc.narg('ip'))
  AND (sqlc.narg('categories')::text[] IS NULL OR audit.activity_category(action) = ANY(sqlc.narg('categories')))
  AND (sqlc.narg('severities')::text[] IS NULL OR audit.activity_severity(action) = ANY(sqlc.narg('severities')))
  AND (sqlc.narg('min_severity')::text IS NULL
       OR array_position(ARRAY['info', 'success', 'warning', 'error', 'critical'], audit.activity_severity(action))
          >= array_position(ARRAY['info', 'success', 'warning', 'error', 'critical'], sqlc.narg('min_severity')::text))
GROUP BY action;

-- name: SummarizeActivityTotals :one
-- Total events and unique-actor counts over the same window. unique_actors
-- (people) cannot be folded from the per-action rows (one actor spans many
-- actions), so it needs its own aggregate pass. API keys, agents and service
-- principals are told apart by the metadata.actor_id their events record.
SELECT count(*)::bigint AS total,
       count(DISTINCT actor_user_id) FILTER (WHERE actor_type = 'user')::bigint AS unique_actors,
       count(DISTINCT metadata->>'actor_id') FILTER (WHERE actor_type = 'api_key')::bigint AS unique_api_keys,
       count(DISTINCT metadata->>'actor_id') FILTER (WHERE actor_type = 'agent')::bigint AS unique_agents,
       count(DISTINCT metadata->>'actor_id') FILTER (WHERE actor_type = 'service')::bigint AS unique_services
FROM audit.events
WHERE audit.events.organization_id = @organization_id
  AND (sqlc.narg('actions')::text[] IS NULL OR action = ANY(sqlc.narg('actions')))
  AND (sqlc.narg('actor_id')::uuid IS NULL OR actor_user_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('subject')::uuid IS NULL OR actor_user_id = sqlc.narg('subject') OR (resource_type = 'user' AND resource_id = sqlc.narg('subject')) OR metadata->>'user_id' = sqlc.narg('subject')::uuid::text)
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR created_at <= sqlc.narg('to_ts'))
  AND (sqlc.narg('q')::text IS NULL OR search_vector @@ audit.search_query(sqlc.narg('q'))
       OR actor_user_id IN (SELECT su.id FROM account.users su
           WHERE (su.email ILIKE sqlc.narg('q_like')::text || '%' OR su.display_name ILIKE '%' || sqlc.narg('q_like')::text || '%')
             AND (su.organization_id = @organization_id OR su.id IN (SELECT sr.user_id FROM rbac.user_roles sr WHERE sr.organization_id = @organization_id))))
  AND (sqlc.narg('resource_types')::text[] IS NULL OR resource_type = ANY(sqlc.narg('resource_types')))
  AND (sqlc.narg('resource_id')::uuid IS NULL OR resource_id = sqlc.narg('resource_id'))
  AND (sqlc.narg('ip')::inet IS NULL OR ip = sqlc.narg('ip'))
  AND (sqlc.narg('categories')::text[] IS NULL OR audit.activity_category(action) = ANY(sqlc.narg('categories')))
  AND (sqlc.narg('severities')::text[] IS NULL OR audit.activity_severity(action) = ANY(sqlc.narg('severities')))
  AND (sqlc.narg('min_severity')::text IS NULL
       OR array_position(ARRAY['info', 'success', 'warning', 'error', 'critical'], audit.activity_severity(action))
          >= array_position(ARRAY['info', 'success', 'warning', 'error', 'critical'], sqlc.narg('min_severity')::text));

-- name: SummarizeActivityTimeSeries :many
-- Per-bucket, per-action counts for sparklines. Bucket width = @bucket_seconds.
-- Grouped by action too so the handler can fold each bucket into per-outcome
-- series (severity/outcome are derived from action in Go, not columns). Empty
-- buckets are omitted (the frontend fills gaps). Same predicates as history.
SELECT (to_timestamp(floor(extract(epoch FROM created_at) / @bucket_seconds::bigint) * @bucket_seconds::bigint))::timestamptz AS bucket,
       action,
       count(*)::bigint AS count
FROM audit.events
WHERE audit.events.organization_id = @organization_id
  AND (sqlc.narg('actions')::text[] IS NULL OR action = ANY(sqlc.narg('actions')))
  AND (sqlc.narg('actor_id')::uuid IS NULL OR actor_user_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('subject')::uuid IS NULL OR actor_user_id = sqlc.narg('subject') OR (resource_type = 'user' AND resource_id = sqlc.narg('subject')) OR metadata->>'user_id' = sqlc.narg('subject')::uuid::text)
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR created_at <= sqlc.narg('to_ts'))
  AND (sqlc.narg('q')::text IS NULL OR search_vector @@ audit.search_query(sqlc.narg('q'))
       OR actor_user_id IN (SELECT su.id FROM account.users su
           WHERE (su.email ILIKE sqlc.narg('q_like')::text || '%' OR su.display_name ILIKE '%' || sqlc.narg('q_like')::text || '%')
             AND (su.organization_id = @organization_id OR su.id IN (SELECT sr.user_id FROM rbac.user_roles sr WHERE sr.organization_id = @organization_id))))
  AND (sqlc.narg('resource_types')::text[] IS NULL OR resource_type = ANY(sqlc.narg('resource_types')))
  AND (sqlc.narg('resource_id')::uuid IS NULL OR resource_id = sqlc.narg('resource_id'))
  AND (sqlc.narg('ip')::inet IS NULL OR ip = sqlc.narg('ip'))
  AND (sqlc.narg('categories')::text[] IS NULL OR audit.activity_category(action) = ANY(sqlc.narg('categories')))
  AND (sqlc.narg('severities')::text[] IS NULL OR audit.activity_severity(action) = ANY(sqlc.narg('severities')))
  AND (sqlc.narg('min_severity')::text IS NULL
       OR array_position(ARRAY['info', 'success', 'warning', 'error', 'critical'], audit.activity_severity(action))
          >= array_position(ARRAY['info', 'success', 'warning', 'error', 'critical'], sqlc.narg('min_severity')::text))
GROUP BY bucket, action
ORDER BY bucket ASC;

-- name: GetActivityEventByID :one
-- Anchor lookup for related-events correlation, organization-scoped. Returns
-- pgx.ErrNoRows when the id is unknown OR belongs to another organization, so a
-- cross-organization fetch surfaces as 404 (never a leak).
SELECT e.id, e.actor_user_id, e.actor_type, e.action, e.resource_type, e.resource_id,
       COALESCE(host(e.ip), '')::text AS ip, e.user_agent, e.request_id, e.created_at, e.metadata, e.organization_id,
       u.display_name AS actor_display_name, u.email AS actor_email
FROM audit.events e
LEFT JOIN account.users u ON u.id = e.actor_user_id AND u.organization_id = e.organization_id
WHERE e.organization_id = @organization_id AND e.id = @id;

-- name: ListRelatedByRequestID :many
-- Other events sharing the anchor's request_id. Caller only runs this when the
-- anchor's request_id is non-empty.
SELECT e.id, e.actor_user_id, e.actor_type, e.action, e.resource_type, e.resource_id,
       COALESCE(host(e.ip), '')::text AS ip, e.user_agent, e.request_id, e.created_at, e.metadata, e.organization_id,
       u.display_name AS actor_display_name, u.email AS actor_email
FROM audit.events e
LEFT JOIN account.users u ON u.id = e.actor_user_id AND u.organization_id = e.organization_id
WHERE e.organization_id = @organization_id
  AND e.request_id = @request_id
  AND e.id <> @exclude_id
ORDER BY e.created_at ASC, e.id ASC
LIMIT @row_limit;

-- name: ListRelatedByActor :many
-- Same actor within [@from_ts, @to_ts] (a symmetric window around the anchor),
-- excluding the anchor. Ordered newest-first for parity with history.
SELECT e.id, e.actor_user_id, e.actor_type, e.action, e.resource_type, e.resource_id,
       COALESCE(host(e.ip), '')::text AS ip, e.user_agent, e.request_id, e.created_at, e.metadata, e.organization_id,
       u.display_name AS actor_display_name, u.email AS actor_email
FROM audit.events e
LEFT JOIN account.users u ON u.id = e.actor_user_id AND u.organization_id = e.organization_id
WHERE e.organization_id = @organization_id
  AND e.actor_user_id = @actor_id
  AND e.created_at BETWEEN @from_ts AND @to_ts
  AND e.id <> @exclude_id
ORDER BY e.created_at DESC, e.id DESC
LIMIT @row_limit;
