-- Queries for the threat-detection/threat domain, compiled by sqlc into ./dbgen.

-- name: GetUserForAnomaly :one
SELECT id, organization_id FROM account.users
WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL AND organization_id IS NOT NULL
LIMIT 1;

-- name: InsertSecurityEvent :exec
-- An empty @ip or @user_agent is recorded as NULL.
INSERT INTO auth.security_events (organization_id, user_id, type, severity, detail, status, ip, user_agent, metadata)
VALUES (@organization_id, sqlc.narg('user_id'), @type, @severity, @detail, @status,
        NULLIF(@ip::text, '')::inet, NULLIF(@user_agent::text, ''), @metadata);

-- name: ListOrganizationsForEmails :many
-- The organizations the given (lowercased) addresses belong to.
SELECT DISTINCT organization_id::uuid AS organization_id FROM account.users
WHERE LOWER(email) = ANY(@emails::text[]) AND deleted_at IS NULL AND organization_id IS NOT NULL;

-- name: ListOrganizationUsersForEmails :many
-- The accounts of one organization among the given (lowercased) addresses.
SELECT id FROM account.users
WHERE organization_id = @organization_id::uuid AND LOWER(email) = ANY(@emails::text[]) AND deleted_at IS NULL;

-- name: CountSecurityEvents :one
-- The organization's anomalies, of @status unless it is empty.
SELECT count(*) FROM auth.security_events
WHERE organization_id = @organization_id AND (@status::text = '' OR status = @status::text);

-- name: ListSecurityEvents :many
-- A page of CountSecurityEvents' anomalies, newest first, before the cursor
-- (before_ts, before_id) when it is set; ip is '' when none was recorded.
SELECT e.id, e.type, e.severity, e.detail, e.status, e.user_id, u.email AS user_email,
       COALESCE(host(e.ip), '')::text AS ip, e.metadata, e.created_at, e.resolved_at, e.resolved_by, rb.email AS resolved_by_email
FROM auth.security_events e
LEFT JOIN account.users u ON u.id = e.user_id
LEFT JOIN account.users rb ON rb.id = e.resolved_by
WHERE e.organization_id = @organization_id AND (@status::text = '' OR e.status = @status::text)
  AND (sqlc.narg('before_ts')::timestamptz IS NULL
       OR (e.created_at, e.id) < (sqlc.narg('before_ts')::timestamptz, sqlc.narg('before_id')::uuid))
ORDER BY e.created_at DESC, e.id DESC
LIMIT @lim;

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
        WHERE open_event.organization_id = $1 AND open_event.resolved_at IS NULL AND open_event.user_id IS NOT NULL
        UNION ALL
        SELECT targeted.id::uuid FROM auth.security_events open_event,
               jsonb_array_elements_text(COALESCE(open_event.metadata->'targeted_user_ids', '[]'::jsonb)) AS targeted(id)
        WHERE open_event.organization_id = $1 AND open_event.resolved_at IS NULL
    ) accounts)                                                                          AS affected_accounts,
    COUNT(*) FILTER (WHERE severity IN ('high', 'critical') AND created_at >= NOW() - INTERVAL '24 hours') AS high_severity_24h
FROM auth.security_events
WHERE organization_id = $1;

-- ResolveSecurityEvent returns what the resolved anomaly was, for its audit
-- record.
-- name: ResolveSecurityEvent :one
UPDATE auth.security_events
SET status = 'resolved', resolved_at = NOW(), resolved_by = sqlc.narg('resolved_by')
WHERE id = @id AND organization_id = @organization_id AND resolved_at IS NULL
RETURNING type, severity, user_id;
