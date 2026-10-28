-- Queries for the audit domain.
--
-- The hash-chained append-only audit log.  Static queries are here; dynamic
-- ones stay hand-written in the respective .go files:
--   - Reader.List (http.go): dynamic WHERE clause with optional action, resource
--     type, actor, free-text search, and cursor filters.
--   - Record advisory-lock call (audit.go): pg_advisory_xact_lock is a
--     void-returning side-effect function; it stays as a raw tx.Exec call.

-- name: GetAuditChainTip :one
-- Fetch the most recent row_hash and created_at for a tenant's chain, or, when
-- tenant_id is NULL, for platform chain chain_shard. Called by Record() inside
-- the caller's transaction to chain the next row. One branch per kind of chain,
-- the other always empty, so each is an index scan (idx_audit_chain_tip, and
-- idx_audit_platform_chain): IS NOT DISTINCT FROM can't use an index and read
-- the whole table on every audited action.
(SELECT o.row_hash, o.created_at FROM audit.events o
 WHERE o.tenant_id = @tenant_id AND o.row_hash IS NOT NULL
 ORDER BY o.created_at DESC, o.id DESC LIMIT 1)
UNION ALL
(SELECT p.row_hash, p.created_at FROM audit.events p
 WHERE @tenant_id::uuid IS NULL AND p.tenant_id IS NULL AND p.chain_shard = @chain_shard AND p.row_hash IS NOT NULL
 ORDER BY p.created_at DESC, p.id DESC LIMIT 1)
LIMIT 1;

-- name: InsertAuditEvent :exec
-- Append one row to the hash-chained audit log.  Column order matches the
-- canonicalRow struct in audit.go — never reorder.  ip is stored as inet;
-- NULLIF converts an empty string to NULL before the cast so empty IPs are
-- stored cleanly rather than causing a parse error.
INSERT INTO audit.events (
    id, tenant_id, actor_user_id, actor_type, action,
    resource_type, resource_id, ip, user_agent, request_id,
    metadata, created_at, prev_hash, row_hash, chain_shard
) VALUES (
    @id, @tenant_id, @actor_user_id, @actor_type, @action,
    @resource_type, @resource_id, NULLIF(@ip, '')::inet, @user_agent, @request_id,
    @metadata, @created_at, @prev_hash, @row_hash, @chain_shard
);

-- name: ListAuditEventsForVerify :many
-- Walk the chain in chronological insert order for hash-chain verification,
-- one page after (after_created_at, after_id) at a time: a tenant's chain, or
-- platform chain chain_shard when tenant_id is NULL, each branch an index scan
-- (see GetAuditChainTip). Only rows with non-NULL hashes (post-hash-chain migration)
-- are returned. COALESCE on optional fields ensures the canonical bytes match
-- what Record wrote at insert time regardless of how Postgres stored the values.
(SELECT o.id, o.tenant_id, o.actor_user_id, o.actor_type, o.action,
        o.resource_type, o.resource_id,
        COALESCE(host(o.ip), '') AS ip,
        COALESCE(o.user_agent, '') AS user_agent,
        COALESCE(o.request_id, '') AS request_id,
        o.metadata,
        o.created_at,
        o.prev_hash, o.row_hash, o.chain_shard
 FROM audit.events o
 WHERE o.tenant_id = @tenant_id AND o.row_hash IS NOT NULL
   AND (o.created_at, o.id) > (@after_created_at::timestamptz, @after_id::uuid)
 ORDER BY o.created_at ASC, o.id ASC
 LIMIT @page_size)
UNION ALL
(SELECT p.id, p.tenant_id, p.actor_user_id, p.actor_type, p.action,
        p.resource_type, p.resource_id,
        COALESCE(host(p.ip), '') AS ip,
        COALESCE(p.user_agent, '') AS user_agent,
        COALESCE(p.request_id, '') AS request_id,
        p.metadata,
        p.created_at,
        p.prev_hash, p.row_hash, p.chain_shard
 FROM audit.events p
 WHERE @tenant_id::uuid IS NULL AND p.tenant_id IS NULL AND p.chain_shard = @chain_shard AND p.row_hash IS NOT NULL
   AND (p.created_at, p.id) > (@after_created_at::timestamptz, @after_id::uuid)
 ORDER BY p.created_at ASC, p.id ASC
 LIMIT @page_size)
ORDER BY created_at ASC, id ASC;

-- name: GetAuditEventForVerify :one
-- One row of a chain, as ListAuditEventsForVerify reads it: the row a chain's
-- checkpoint names, checked again before the walk goes on after it.
(SELECT o.id, o.tenant_id, o.actor_user_id, o.actor_type, o.action,
        o.resource_type, o.resource_id,
        COALESCE(host(o.ip), '') AS ip,
        COALESCE(o.user_agent, '') AS user_agent,
        COALESCE(o.request_id, '') AS request_id,
        o.metadata,
        o.created_at,
        o.prev_hash, o.row_hash, o.chain_shard
 FROM audit.events o
 WHERE o.id = @id AND o.tenant_id = @tenant_id AND o.row_hash IS NOT NULL)
UNION ALL
(SELECT p.id, p.tenant_id, p.actor_user_id, p.actor_type, p.action,
        p.resource_type, p.resource_id,
        COALESCE(host(p.ip), '') AS ip,
        COALESCE(p.user_agent, '') AS user_agent,
        COALESCE(p.request_id, '') AS request_id,
        p.metadata,
        p.created_at,
        p.prev_hash, p.row_hash, p.chain_shard
 FROM audit.events p
 WHERE p.id = @id AND @tenant_id::uuid IS NULL AND p.tenant_id IS NULL AND p.chain_shard = @chain_shard AND p.row_hash IS NOT NULL);

-- name: FindAuditRowOutsideShards :one
-- A platform row whose chain_shard is not one of the @shards platform chains,
-- which no chain's verification would read: the first, if any.
SELECT e.id, e.chain_shard FROM audit.events e
WHERE e.tenant_id IS NULL AND e.row_hash IS NOT NULL AND (e.chain_shard < 0 OR e.chain_shard >= @shards::smallint)
ORDER BY e.chain_shard, e.created_at, e.id
LIMIT 1;

-- name: ListAuditChainTenants :many
-- Every organisation with a hash chain, for the scheduled verification of all
-- of them (the platform chains, NULL tenant_id, are verified separately). It
-- skips from one organisation to the next along idx_audit_chain_tip, reading a
-- row per organisation rather than every row.
WITH RECURSIVE chains AS (
    (SELECT e.tenant_id FROM audit.events e
     WHERE e.tenant_id IS NOT NULL AND e.row_hash IS NOT NULL
     ORDER BY e.tenant_id LIMIT 1)
    UNION ALL
    SELECT (SELECT e.tenant_id FROM audit.events e
            WHERE e.tenant_id > c.tenant_id AND e.row_hash IS NOT NULL
            ORDER BY e.tenant_id LIMIT 1)
    FROM chains c
    WHERE c.tenant_id IS NOT NULL
)
SELECT chains.tenant_id::uuid AS tenant_id FROM chains WHERE chains.tenant_id IS NOT NULL;

-- name: ListAuditChainCheckpoints :many
-- Every chain's checkpoint: the last row a scheduled verification found intact,
-- and whether the chain has since been found broken.
SELECT tenant_id, chain_shard, event_id, event_created_at, row_hash, (broken_at IS NOT NULL)::bool AS broken
FROM platform.audit_chain_checkpoints;

-- name: InsertAuditChainCheckpoint :exec
-- A chain's first checkpoint. A run that began when it had none leaves one
-- another run wrote since.
INSERT INTO platform.audit_chain_checkpoints (tenant_id, chain_shard, event_id, event_created_at, row_hash)
VALUES (@tenant_id, @chain_shard, @event_id, @event_created_at, @row_hash)
ON CONFLICT (tenant_id, chain_shard) DO NOTHING;

-- name: AdvanceAuditChainCheckpoint :exec
-- Move a chain's checkpoint on from the one the run began at, unless another
-- run has moved it or found the chain broken since.
UPDATE platform.audit_chain_checkpoints
SET event_id = @event_id, event_created_at = @event_created_at, row_hash = @row_hash, verified_at = NOW()
WHERE event_id = @from_event_id AND broken_at IS NULL AND chain_shard = @chain_shard
  AND (tenant_id = @tenant_id OR (@tenant_id::uuid IS NULL AND tenant_id IS NULL));

-- name: MarkAuditChainCheckpointBroken :exec
-- Mark a chain broken at the checkpoint the run began at. The checkpoint then
-- stays, and every run checks its row again and walks the chain from the start.
UPDATE platform.audit_chain_checkpoints
SET broken_at = COALESCE(broken_at, NOW())
WHERE event_id = @event_id AND chain_shard = @chain_shard
  AND (tenant_id = @tenant_id OR (@tenant_id::uuid IS NULL AND tenant_id IS NULL));

-- name: CountFullAuditVerificationsSince :one
-- How many verifications since @since walked every chain from its first row;
-- one that failed to run doesn't count.
SELECT count(*) FROM platform.audit_verification_runs
WHERE scope = 'all' AND outcome <> 'error' AND started_at > @since;

-- name: InsertAuditVerificationRun :exec
-- Store one scheduled verification of every chain, as evidence. Its scope is
-- 'all' when it walked each chain from its first row, 'incremental' when from
-- the chains' checkpoints.
INSERT INTO platform.audit_verification_runs (
    id, started_at, finished_at, scope, tenants_walked, rows_checked, outcome,
    broken_tenant_id, first_broken_link, broken_reason, error
) VALUES (
    @id, @started_at, @finished_at, @scope, @tenants_walked, @rows_checked, @outcome,
    sqlc.narg(broken_tenant_id), sqlc.narg(first_broken_link), sqlc.narg(broken_reason), sqlc.narg(error)
);

-- name: LastIntactAuditVerification :one
-- When a scheduled verification last found every chain intact (0: never).
SELECT COALESCE(extract(epoch FROM max(finished_at)), 0)::float8 AS at
FROM platform.audit_verification_runs WHERE outcome = 'intact';

-- name: GetTenantChainCheckpoint :one
-- One organisation's chain as the scheduled verification last left it.
SELECT event_id, event_created_at, verified_at, broken_at
FROM platform.audit_chain_checkpoints
WHERE tenant_id = @tenant_id::uuid;

-- name: GetLatestVerificationRun :one
SELECT finished_at, scope FROM platform.audit_verification_runs ORDER BY started_at DESC LIMIT 1;
