-- Queries for the threat-detection/threat domain.
-- Static queries are compiled by sqlc into ./dbgen.
-- InsertSecurityEvent is intentionally hand-written in threat.go because it
-- uses NULLIF($7,'')::inet — the inet cast makes sqlc parameter-type inference
-- ambiguous; correctness takes priority over coverage.

-- name: GetUserForAnomaly :one
SELECT id, tenant_id FROM "user".users
WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL AND tenant_id IS NOT NULL
LIMIT 1;

-- name: ListTenantsForEmails :many
-- The organisations the given (lowercased) addresses belong to.
SELECT DISTINCT tenant_id::uuid AS tenant_id FROM "user".users
WHERE LOWER(email) = ANY(@emails::text[]) AND deleted_at IS NULL AND tenant_id IS NOT NULL;

-- name: ListTenantUsersForEmails :many
-- The accounts of one organisation among the given (lowercased) addresses.
SELECT id FROM "user".users
WHERE tenant_id = @tenant_id::uuid AND LOWER(email) = ANY(@emails::text[]) AND deleted_at IS NULL;

-- ListSecurityEvents is intentionally hand-written in threat.go because
-- COALESCE(host(e.ip),'') causes sqlc to generate interface{} for the column,
-- making type-safe scanning impossible without runtime assertions.

-- GetSecurityEventSummary feeds the KPI cards. An event is open until it is
-- resolved, whatever its status says: the lockout detections record theirs as
-- rate-limited. High severity includes critical. Affected accounts counts the
-- account an open event names and those a spray targeted (targeted_user_ids).
-- name: GetSecurityEventSummary :one
SELECT
    COUNT(*) FILTER (WHERE resolved_at IS NULL)                                           AS open,
    COUNT(*) FILTER (WHERE resolved_at >= NOW() - INTERVAL '24 hours')                   AS resolved_24h,
    (SELECT count(DISTINCT account)::bigint FROM (
        SELECT open_event.user_id AS account FROM auth.security_events open_event
        WHERE open_event.tenant_id = $1 AND open_event.resolved_at IS NULL AND open_event.user_id IS NOT NULL
        UNION ALL
        SELECT targeted.id::uuid FROM auth.security_events open_event,
               jsonb_array_elements_text(COALESCE(open_event.metadata->'targeted_user_ids', '[]'::jsonb)) AS targeted(id)
        WHERE open_event.tenant_id = $1 AND open_event.resolved_at IS NULL
    ) accounts)                                                                          AS affected_accounts,
    COUNT(*) FILTER (WHERE severity IN ('high', 'critical') AND created_at >= NOW() - INTERVAL '24 hours') AS high_severity_24h
FROM auth.security_events
WHERE tenant_id = $1;

-- ResolveSecurityEvent returns what the resolved anomaly was, for its audit
-- record.
-- name: ResolveSecurityEvent :one
UPDATE auth.security_events
SET status = 'resolved', resolved_at = NOW(), resolved_by = sqlc.narg('resolved_by')
WHERE id = @id AND tenant_id = @tenant_id AND resolved_at IS NULL
RETURNING type, severity, user_id;
