-- Queries for the audit domain.
--
-- Reading, verifying and purging the hash-chained audit log; the writer and
-- its queries are internal/platform/audit. Reader.List (list.go) stays
-- hand-written: a dynamic WHERE clause with optional action, resource type,
-- actor, free-text search, and cursor filters.

-- name: ListAuditEventsForVerify :many
-- Walk the chain in chronological insert order for hash-chain verification,
-- one page after (after_created_at, after_id) at a time: an organization's chain, or
-- platform chain chain_shard when organization_id is NULL, each branch an index scan
-- (see GetAuditChainTip). Only rows with non-NULL hashes (post-hash-chain migration)
-- are returned. COALESCE on optional fields ensures the canonical bytes match
-- what Record wrote at insert time regardless of how Postgres stored the values.
(SELECT o.id, o.organization_id, o.actor_user_id, o.actor_type, o.action,
        o.resource_type, o.resource_id,
        COALESCE(host(o.ip), '') AS ip,
        COALESCE(o.user_agent, '') AS user_agent,
        COALESCE(o.request_id, '') AS request_id,
        o.metadata,
        o.created_at,
        o.prev_hash, o.row_hash, o.chain_shard
 FROM audit.events o
 WHERE o.organization_id = @organization_id AND o.row_hash IS NOT NULL
   AND (o.created_at, o.id) > (@after_created_at::timestamptz, @after_id::uuid)
 ORDER BY o.created_at ASC, o.id ASC
 LIMIT @page_size)
UNION ALL
(SELECT p.id, p.organization_id, p.actor_user_id, p.actor_type, p.action,
        p.resource_type, p.resource_id,
        COALESCE(host(p.ip), '') AS ip,
        COALESCE(p.user_agent, '') AS user_agent,
        COALESCE(p.request_id, '') AS request_id,
        p.metadata,
        p.created_at,
        p.prev_hash, p.row_hash, p.chain_shard
 FROM audit.events p
 WHERE @organization_id::uuid IS NULL AND p.organization_id IS NULL AND p.chain_shard = @chain_shard AND p.row_hash IS NOT NULL
   AND (p.created_at, p.id) > (@after_created_at::timestamptz, @after_id::uuid)
 ORDER BY p.created_at ASC, p.id ASC
 LIMIT @page_size)
ORDER BY created_at ASC, id ASC;

-- name: GetAuditEventForVerify :one
-- One row of a chain, as ListAuditEventsForVerify reads it: the row a chain's
-- checkpoint names, checked again before the walk goes on after it.
(SELECT o.id, o.organization_id, o.actor_user_id, o.actor_type, o.action,
        o.resource_type, o.resource_id,
        COALESCE(host(o.ip), '') AS ip,
        COALESCE(o.user_agent, '') AS user_agent,
        COALESCE(o.request_id, '') AS request_id,
        o.metadata,
        o.created_at,
        o.prev_hash, o.row_hash, o.chain_shard
 FROM audit.events o
 WHERE o.id = @id AND o.organization_id = @organization_id AND o.row_hash IS NOT NULL)
UNION ALL
(SELECT p.id, p.organization_id, p.actor_user_id, p.actor_type, p.action,
        p.resource_type, p.resource_id,
        COALESCE(host(p.ip), '') AS ip,
        COALESCE(p.user_agent, '') AS user_agent,
        COALESCE(p.request_id, '') AS request_id,
        p.metadata,
        p.created_at,
        p.prev_hash, p.row_hash, p.chain_shard
 FROM audit.events p
 WHERE p.id = @id AND @organization_id::uuid IS NULL AND p.organization_id IS NULL AND p.chain_shard = @chain_shard AND p.row_hash IS NOT NULL);

-- name: FindAuditRowOutsideShards :one
-- A platform row whose chain_shard is not one of the @shards platform chains,
-- which no chain's verification would read: the first, if any.
SELECT e.id, e.chain_shard FROM audit.events e
WHERE e.organization_id IS NULL AND e.row_hash IS NOT NULL AND (e.chain_shard < 0 OR e.chain_shard >= @shards::smallint)
ORDER BY e.chain_shard, e.created_at, e.id
LIMIT 1;

-- name: ListAuditChainOrganizations :many
-- Every organization with a hash chain, for the scheduled verification of all
-- of them (the platform chains, NULL organization_id, are verified separately). It
-- skips from one organization to the next along idx_audit_chain_tip, reading a
-- row per organization rather than every row.
WITH RECURSIVE chains AS (
    (SELECT e.organization_id FROM audit.events e
     WHERE e.organization_id IS NOT NULL AND e.row_hash IS NOT NULL
     ORDER BY e.organization_id LIMIT 1)
    UNION ALL
    SELECT (SELECT e.organization_id FROM audit.events e
            WHERE e.organization_id > c.organization_id AND e.row_hash IS NOT NULL
            ORDER BY e.organization_id LIMIT 1)
    FROM chains c
    WHERE c.organization_id IS NOT NULL
)
SELECT chains.organization_id::uuid AS organization_id FROM chains WHERE chains.organization_id IS NOT NULL;

-- name: ListAuditChainCheckpoints :many
-- Every chain's checkpoint: the last row a scheduled verification found intact,
-- its signature, and whether the chain has since been found broken.
SELECT organization_id, chain_shard, event_id, event_created_at, row_hash, key_id, mac, (broken_at IS NOT NULL)::bool AS broken
FROM platform.audit_chain_checkpoints;

-- name: GetAuditChainCheckpoint :one
-- One chain's checkpoint, as ListAuditChainCheckpoints reads it: an
-- organization's chain, or platform chain chain_shard when organization_id is NULL.
SELECT event_id, event_created_at, row_hash, key_id, mac FROM platform.audit_chain_checkpoints
WHERE chain_shard = @chain_shard
  AND (organization_id = sqlc.narg(organization_id)::uuid OR (sqlc.narg(organization_id)::uuid IS NULL AND organization_id IS NULL));

-- name: InsertAuditChainCheckpoint :exec
-- A chain's first checkpoint. A run that began when it had none leaves one
-- another run wrote since.
INSERT INTO platform.audit_chain_checkpoints (organization_id, chain_shard, event_id, event_created_at, row_hash, key_id, mac)
VALUES (@organization_id, @chain_shard, @event_id, @event_created_at, @row_hash, sqlc.narg(key_id), sqlc.narg(mac))
ON CONFLICT (organization_id, chain_shard) DO NOTHING;

-- name: AdvanceAuditChainCheckpoint :exec
-- Move a chain's checkpoint on from the one the run began at, or sign it again
-- with the current key, unless another run has moved it or found the chain
-- broken since.
UPDATE platform.audit_chain_checkpoints
SET event_id = @event_id, event_created_at = @event_created_at, row_hash = @row_hash,
    key_id = sqlc.narg(key_id), mac = sqlc.narg(mac), verified_at = NOW()
WHERE event_id = @from_event_id AND broken_at IS NULL AND chain_shard = @chain_shard
  AND (organization_id = @organization_id OR (@organization_id::uuid IS NULL AND organization_id IS NULL));

-- name: MarkAuditChainCheckpointBroken :exec
-- Mark a chain broken at the checkpoint the run began at. The checkpoint then
-- stays, and every run checks its row again and walks the chain from the start.
UPDATE platform.audit_chain_checkpoints
SET broken_at = COALESCE(broken_at, NOW())
WHERE event_id = @event_id AND chain_shard = @chain_shard
  AND (organization_id = @organization_id OR (@organization_id::uuid IS NULL AND organization_id IS NULL));

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
    id, started_at, finished_at, scope, organizations_walked, rows_checked, outcome,
    broken_organization_id, first_broken_link, broken_reason, error
) VALUES (
    @id, @started_at, @finished_at, @scope, @organizations_walked, @rows_checked, @outcome,
    sqlc.narg(broken_organization_id), sqlc.narg(first_broken_link), sqlc.narg(broken_reason), sqlc.narg(error)
);

-- name: LastIntactAuditVerification :one
-- When a scheduled verification last found every chain intact (0: never).
SELECT COALESCE(extract(epoch FROM max(finished_at)), 0)::float8 AS at
FROM platform.audit_verification_runs WHERE outcome = 'intact';

-- name: GetOrganizationChainCheckpoint :one
-- One organization's chain as the scheduled verification last left it.
SELECT event_id, event_created_at, verified_at, broken_at
FROM platform.audit_chain_checkpoints
WHERE organization_id = @organization_id::uuid;

-- name: GetLatestVerificationRun :one
SELECT finished_at, scope FROM platform.audit_verification_runs ORDER BY started_at DESC LIMIT 1;

-- ==========================================================================
-- Retention
-- ==========================================================================

-- name: ListRetentionOrganizations :many
-- Every organization, for the audit retention job to ask how long its plan
-- keeps events.
SELECT id FROM organization.organizations ORDER BY id;

-- name: AuditChainBroken :one
-- Whether the scheduled verification found an organization's chain broken.
SELECT EXISTS (
    SELECT 1 FROM platform.audit_chain_checkpoints
    WHERE organization_id = @organization_id::uuid AND broken_at IS NOT NULL
)::bool;

-- name: ListAuditEventsToPurge :many
-- The oldest of an organization's chained events sent before cutoff, never its
-- newest (the tip the next event links to), in chain order.
SELECT o.id, o.created_at, o.row_hash
FROM audit.events o
WHERE o.organization_id = @organization_id::uuid AND o.row_hash IS NOT NULL AND o.created_at < @cutoff
  AND EXISTS (
      SELECT 1 FROM audit.events n
      WHERE n.organization_id = o.organization_id AND (n.created_at, n.id) > (o.created_at, o.id)
  )
ORDER BY o.created_at ASC, o.id ASC
LIMIT @batch;

-- name: SetAuditPurgeCheckpoint :exec
-- Where an organization's chain starts once its events up to and including
-- event_id are deleted.
INSERT INTO platform.audit_purge_checkpoints (organization_id, event_id, event_created_at, row_hash, events_purged, key_id, mac)
VALUES (@organization_id, @event_id, @event_created_at, @row_hash, @purged, sqlc.narg(key_id), sqlc.narg(mac))
ON CONFLICT (organization_id) DO UPDATE SET
    event_id = EXCLUDED.event_id, event_created_at = EXCLUDED.event_created_at, row_hash = EXCLUDED.row_hash,
    key_id = EXCLUDED.key_id, mac = EXCLUDED.mac,
    events_purged = audit_purge_checkpoints.events_purged + EXCLUDED.events_purged, purged_at = NOW();

-- name: DeleteAuditEventsThrough :execrows
-- Deletes an organization's events up to and including (created_at, id) in
-- chain order.
DELETE FROM audit.events
WHERE organization_id = @organization_id::uuid AND (created_at, id) <= (@created_at::timestamptz, @id::uuid);

-- name: GetAuditPurgeCheckpoint :one
-- Where an organization's chain starts since its oldest events were deleted.
SELECT event_id, event_created_at, row_hash, key_id, mac FROM platform.audit_purge_checkpoints
WHERE organization_id = @organization_id::uuid;

-- name: SignAuditPurgeCheckpoint :exec
-- Sign an organization's purge checkpoint again, with the current key, unless
-- a purge has moved it since.
UPDATE platform.audit_purge_checkpoints SET key_id = @key_id, mac = @mac
WHERE organization_id = @organization_id AND event_id = @event_id;
