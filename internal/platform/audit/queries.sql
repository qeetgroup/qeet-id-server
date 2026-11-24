-- Queries for the audit writer: the tip of a chain, the row appended to it,
-- and the names of what an event is about. The advisory lock that serialises
-- a chain's writers (audit.go) stays a raw tx.Exec call: pg_advisory_xact_lock
-- returns void, which sqlc cannot model.

-- name: GetAuditChainTip :one
-- Fetch the most recent row_hash and created_at for an organization's chain, or, when
-- organization_id is NULL, for platform chain chain_shard. Called by Record() inside
-- the caller's transaction to chain the next row. One branch per kind of chain,
-- the other always empty, so each is an index scan (idx_audit_chain_tip, and
-- idx_audit_platform_chain): IS NOT DISTINCT FROM can't use an index and read
-- the whole table on every audited action.
(SELECT o.row_hash, o.created_at FROM audit.events o
 WHERE o.organization_id = @organization_id AND o.row_hash IS NOT NULL
 ORDER BY o.created_at DESC, o.id DESC LIMIT 1)
UNION ALL
(SELECT p.row_hash, p.created_at FROM audit.events p
 WHERE @organization_id::uuid IS NULL AND p.organization_id IS NULL AND p.chain_shard = @chain_shard AND p.row_hash IS NOT NULL
 ORDER BY p.created_at DESC, p.id DESC LIMIT 1)
LIMIT 1;

-- name: InsertAuditEvent :exec
-- Append one row to the hash-chained audit log.  Column order matches the
-- canonicalRow struct in audit.go — never reorder.  ip is stored as inet;
-- NULLIF converts an empty string to NULL before the cast so empty IPs are
-- stored cleanly rather than causing a parse error.
INSERT INTO audit.events (
    id, organization_id, actor_user_id, actor_type, action,
    resource_type, resource_id, ip, user_agent, request_id,
    metadata, created_at, prev_hash, row_hash, chain_shard
) VALUES (
    @id, @organization_id, @actor_user_id, @actor_type, @action,
    @resource_type, @resource_id, NULLIF(@ip, '')::inet, @user_agent, @request_id,
    @metadata, @created_at, @prev_hash, @row_hash, @chain_shard
);

-- The names of what an event is about, as they are now, in the event's
-- organization: no row for an event with none (a NULL @organization_id).

-- name: GetRoleName :one
SELECT name FROM rbac.roles WHERE id = @id AND organization_id = sqlc.narg('organization_id');

-- name: GetGroupName :one
SELECT name FROM organization.groups WHERE id = @id AND organization_id = sqlc.narg('organization_id');

-- name: GetABACPolicyName :one
SELECT name FROM auth.abac_policies WHERE id = @id AND organization_id = sqlc.narg('organization_id');
