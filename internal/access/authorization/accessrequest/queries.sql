-- Access requests: a person asking their organization for a role, and an
-- administrator's answer. Every query names its organization.

-- name: InsertAccessRequest :one
INSERT INTO rbac.access_requests (organization_id, requester_id, role_id, reason, duration_hours, expires_at)
VALUES (@organization_id, @requester_id, @role_id, @reason, @duration_hours, @expires_at)
RETURNING id;

-- RequestableRole is a role of the organization a person may ask for: any but the
-- system owner role.
-- name: RequestableRole :one
SELECT ro.id, ro.name, ro.description
FROM rbac.roles ro
WHERE ro.id = @role_id AND ro.organization_id = @organization_id AND NOT (ro.is_system AND ro.name = 'owner');

-- name: ListRequestableRoles :many
SELECT ro.id, ro.name, ro.description,
       EXISTS (
           SELECT 1 FROM rbac.user_roles ur
           WHERE ur.user_id = @user_id AND ur.organization_id = ro.organization_id AND ur.role_id = ro.id
       )::boolean AS held
FROM rbac.roles ro
WHERE ro.organization_id = @organization_id AND NOT (ro.is_system AND ro.name = 'owner')
ORDER BY ro.is_system DESC, LOWER(ro.name);

-- HoldsRole: the person holds the role directly (not through a group).
-- name: HoldsRole :one
SELECT EXISTS (
    SELECT 1 FROM rbac.user_roles
    WHERE user_id = @user_id AND organization_id = @organization_id AND role_id = @role_id
)::boolean AS held;

-- name: GetAccessRequest :one
SELECT ar.id, ar.organization_id, ar.requester_id, ar.role_id, ar.reason, ar.duration_hours, ar.status,
       ar.created_at, ar.expires_at, ar.decided_by, ar.decided_at, ar.decision_note, ar.granted,
       ar.access_ends_at, ar.ended_at,
       ro.name AS role_name, ro.description AS role_description,
       COALESCE(u.email, '') AS requester_email, COALESCE(u.display_name, '') AS requester_name,
       COALESCE(d.email, '') AS decider_email, COALESCE(d.display_name, '') AS decider_name
FROM rbac.access_requests ar
JOIN rbac.roles ro ON ro.id = ar.role_id AND ro.organization_id = ar.organization_id
LEFT JOIN account.users u ON u.id = ar.requester_id
LEFT JOIN account.users d ON d.id = ar.decided_by
WHERE ar.id = @id AND ar.organization_id = @organization_id;

-- name: LockPendingAccessRequest :one
SELECT id, requester_id, role_id, duration_hours, expires_at
FROM rbac.access_requests
WHERE id = @id AND organization_id = @organization_id AND status = 'pending'
FOR UPDATE;

-- ListAccessRequests lists the organization's requests, newest first, optionally of
-- one status.
-- name: ListAccessRequests :many
SELECT ar.id, ar.organization_id, ar.requester_id, ar.role_id, ar.reason, ar.duration_hours, ar.status,
       ar.created_at, ar.expires_at, ar.decided_by, ar.decided_at, ar.decision_note, ar.granted,
       ar.access_ends_at, ar.ended_at,
       ro.name AS role_name, ro.description AS role_description,
       COALESCE(u.email, '') AS requester_email, COALESCE(u.display_name, '') AS requester_name,
       COALESCE(d.email, '') AS decider_email, COALESCE(d.display_name, '') AS decider_name
FROM rbac.access_requests ar
JOIN rbac.roles ro ON ro.id = ar.role_id AND ro.organization_id = ar.organization_id
LEFT JOIN account.users u ON u.id = ar.requester_id
LEFT JOIN account.users d ON d.id = ar.decided_by
WHERE ar.organization_id = @organization_id
  AND (sqlc.narg('status')::text IS NULL OR ar.status = sqlc.narg('status')::text)
ORDER BY ar.created_at DESC, ar.id DESC
LIMIT @row_limit;

-- name: ListMyAccessRequests :many
SELECT ar.id, ar.organization_id, ar.requester_id, ar.role_id, ar.reason, ar.duration_hours, ar.status,
       ar.created_at, ar.expires_at, ar.decided_by, ar.decided_at, ar.decision_note, ar.granted,
       ar.access_ends_at, ar.ended_at,
       ro.name AS role_name, ro.description AS role_description,
       COALESCE(u.email, '') AS requester_email, COALESCE(u.display_name, '') AS requester_name,
       COALESCE(d.email, '') AS decider_email, COALESCE(d.display_name, '') AS decider_name
FROM rbac.access_requests ar
JOIN rbac.roles ro ON ro.id = ar.role_id AND ro.organization_id = ar.organization_id
LEFT JOIN account.users u ON u.id = ar.requester_id
LEFT JOIN account.users d ON d.id = ar.decided_by
WHERE ar.organization_id = @organization_id AND ar.requester_id = @requester_id
ORDER BY ar.created_at DESC, ar.id DESC
LIMIT 100;

-- name: CountPendingAccessRequests :one
SELECT COUNT(*) FROM rbac.access_requests WHERE organization_id = @organization_id AND status = 'pending';

-- name: ApproveAccessRequest :exec
UPDATE rbac.access_requests
SET status = 'approved', decided_by = @decided_by, decided_at = NOW(), decision_note = @decision_note,
    granted = @granted, access_ends_at = @access_ends_at
WHERE id = @id AND organization_id = @organization_id AND status = 'pending';

-- name: DenyAccessRequest :exec
UPDATE rbac.access_requests
SET status = 'denied', decided_by = @decided_by, decided_at = NOW(), decision_note = @decision_note
WHERE id = @id AND organization_id = @organization_id AND status = 'pending';

-- name: CancelAccessRequest :execrows
UPDATE rbac.access_requests SET status = 'cancelled'
WHERE id = @id AND organization_id = @organization_id AND requester_id = @requester_id AND status = 'pending';

-- LapsePendingAccessRequests ends requests nobody answered in time, across
-- organizations (the maintenance job), returning them to tell their requesters.
-- name: LapsePendingAccessRequests :many
UPDATE rbac.access_requests SET status = 'expired'
WHERE status = 'pending' AND expires_at <= NOW()
RETURNING id, organization_id, requester_id, role_id;

-- EndingAccess lists approved, time-limited grants whose time is up, across
-- organizations, oldest first, a batch at a time.
-- name: EndingAccess :many
SELECT id, organization_id, requester_id, role_id
FROM rbac.access_requests
WHERE status = 'approved' AND granted AND ended_at IS NULL AND access_ends_at <= NOW()
ORDER BY access_ends_at
LIMIT 100;

-- name: MarkAccessEnded :exec
UPDATE rbac.access_requests SET ended_at = NOW()
WHERE id = @id AND organization_id = @organization_id AND ended_at IS NULL;
