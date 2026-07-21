-- Queries for the threat-detection/threat domain.
-- Static queries are compiled by sqlc into ./dbgen.
-- InsertSecurityEvent is intentionally hand-written in threat.go because it
-- uses NULLIF($7,'')::inet — the inet cast makes sqlc parameter-type inference
-- ambiguous; correctness takes priority over coverage.

-- name: GetUserForAnomaly :one
SELECT id, tenant_id FROM "user".users
WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL AND tenant_id IS NOT NULL
LIMIT 1;

-- ListSecurityEvents is intentionally hand-written in threat.go because
-- COALESCE(host(e.ip),'') causes sqlc to generate interface{} for the column,
-- making type-safe scanning impossible without runtime assertions.

-- name: GetSecurityEventSummary :one
SELECT
    COUNT(*) FILTER (WHERE status = 'open')                                               AS open,
    COUNT(*) FILTER (WHERE resolved_at >= NOW() - INTERVAL '24 hours')                   AS resolved_24h,
    COUNT(DISTINCT user_id) FILTER (WHERE status = 'open' AND user_id IS NOT NULL)       AS affected_accounts,
    COUNT(*) FILTER (WHERE severity = 'high' AND created_at >= NOW() - INTERVAL '24 hours') AS high_severity_24h
FROM auth.security_events
WHERE tenant_id = $1;

-- name: ResolveSecurityEvent :execrows
UPDATE auth.security_events
SET status = 'resolved', resolved_at = NOW()
WHERE id = $1 AND tenant_id = $2 AND resolved_at IS NULL;
