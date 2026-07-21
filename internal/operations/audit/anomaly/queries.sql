-- Queries for the audit anomaly detection domain.
--
-- All queries are static.  The List query is split into two variants
-- (with/without status filter) following the sqlc idiomatic pattern used
-- throughout the codebase for optional filters, rather than building the
-- WHERE clause dynamically in Go.

-- name: GetAnomalySettings :one
-- Load per-tenant anomaly detection settings; returns ErrNoRows when no row
-- exists (the service falls back to package-level defaults in that case).
SELECT enabled, score_threshold, min_baseline_events
FROM audit.anomaly_settings WHERE tenant_id = @tenant_id;

-- name: GetActorBaseline :one
-- Read the rolling counter baseline for one (tenant, actor) pair inside the
-- caller's transaction.  FOR UPDATE serialises concurrent sweeps on the same
-- actor so the fold step is applied exactly once per event.
SELECT event_count, actions, hours, ips
FROM audit.actor_baselines
WHERE tenant_id = @tenant_id AND actor_user_id = @actor_user_id
FOR UPDATE;

-- name: UpsertActorBaseline :exec
-- Write (or create) the baseline counters after folding one event in.
INSERT INTO audit.actor_baselines
    (tenant_id, actor_user_id, event_count, actions, hours, ips, updated_at)
VALUES (@tenant_id, @actor_user_id, @event_count, @actions, @hours, @ips, NOW())
ON CONFLICT (tenant_id, actor_user_id) DO UPDATE SET
    event_count = EXCLUDED.event_count,
    actions     = EXCLUDED.actions,
    hours       = EXCLUDED.hours,
    ips         = EXCLUDED.ips,
    updated_at  = NOW();

-- name: ListUnscoredAuditEvents :many
-- Pick a batch of unscored audit events in chronological order.
-- FOR UPDATE SKIP LOCKED prevents two concurrent sweep workers from picking
-- the same event (mirrors the outbox pattern).
-- COALESCE ensures non-null result for ip (inet is nullable; host() of NULL = NULL).
SELECT id, tenant_id, actor_user_id, action, COALESCE(host(ip), '') AS ip, created_at
FROM audit.events
WHERE scored_at IS NULL
ORDER BY created_at, id
LIMIT @batch_size
FOR UPDATE SKIP LOCKED;

-- name: MarkAuditEventScored :exec
-- Stamp a processed event so it is never re-scored by the sweep.
UPDATE audit.events SET scored_at = NOW() WHERE id = @id;

-- name: InsertAnomaly :exec
-- Persist a scored deviation for admin review.  ON CONFLICT DO NOTHING is
-- idempotent so a sweep retry can never create duplicate anomaly rows.
INSERT INTO audit.anomalies (tenant_id, event_id, actor_user_id, score, reasons)
VALUES (@tenant_id, @event_id, @actor_user_id, @score, @reasons)
ON CONFLICT (event_id) DO NOTHING;

-- name: GetAnomalySummary :one
-- Count open, recently-resolved, and high-score open anomalies for the
-- tenant in a single pass (dashboard KPI cards).
SELECT
    count(*) FILTER (WHERE status = 'open')                                          AS open_count,
    count(*) FILTER (WHERE status = 'resolved' AND resolved_at > NOW() - INTERVAL '7 days') AS resolved_7d,
    count(*) FILTER (WHERE status = 'open' AND score >= 0.85)                        AS high_score
FROM audit.anomalies WHERE tenant_id = @tenant_id;

-- name: ResolveAnomaly :execrows
-- Mark an open anomaly as resolved by a specific user.  Returns 0 rows
-- affected when the anomaly is already resolved, not found, or belongs to a
-- different tenant.
UPDATE audit.anomalies
SET status = 'resolved', resolved_at = NOW(), resolved_by = @resolved_by
WHERE id = @id AND tenant_id = @tenant_id AND status = 'open';

-- name: UpsertAnomalySettings :exec
-- Create or replace per-tenant anomaly detection settings.
INSERT INTO audit.anomaly_settings
    (tenant_id, enabled, score_threshold, min_baseline_events, updated_at)
VALUES (@tenant_id, @enabled, @score_threshold, @min_baseline_events, NOW())
ON CONFLICT (tenant_id) DO UPDATE SET
    enabled             = EXCLUDED.enabled,
    score_threshold     = EXCLUDED.score_threshold,
    min_baseline_events = EXCLUDED.min_baseline_events,
    updated_at          = NOW();

-- name: ListAnomalies :many
-- List all anomalies (open and resolved) for a tenant, most recent first.
SELECT
    a.id, a.tenant_id, a.event_id, a.actor_user_id, u.email,
    a.score, a.reasons, a.status, a.resolved_at, a.resolved_by, a.created_at,
    e.action, e.resource_type, COALESCE(host(e.ip), '') AS ip, e.created_at AS event_at
FROM audit.anomalies a
JOIN audit.events e ON e.id = a.event_id
LEFT JOIN "user".users u ON u.id = a.actor_user_id
WHERE a.tenant_id = @tenant_id
ORDER BY a.created_at DESC
LIMIT @row_limit;

-- name: ListAnomaliesFiltered :many
-- List anomalies for a tenant filtered by status, most recent first.
SELECT
    a.id, a.tenant_id, a.event_id, a.actor_user_id, u.email,
    a.score, a.reasons, a.status, a.resolved_at, a.resolved_by, a.created_at,
    e.action, e.resource_type, COALESCE(host(e.ip), '') AS ip, e.created_at AS event_at
FROM audit.anomalies a
JOIN audit.events e ON e.id = a.event_id
LEFT JOIN "user".users u ON u.id = a.actor_user_id
WHERE a.tenant_id = @tenant_id AND a.status = @status
ORDER BY a.created_at DESC
LIMIT @row_limit;
