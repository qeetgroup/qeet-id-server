-- Queries for the audit domain.
--
-- The hash-chained append-only audit log.  Static queries are here; dynamic
-- ones stay hand-written in the respective .go files:
--   - Reader.List (http.go): dynamic WHERE clause with optional action, resource
--     type, actor, free-text search, and cursor filters.
--   - Record advisory-lock call (audit.go): pg_advisory_xact_lock is a
--     void-returning side-effect function; it stays as a raw tx.Exec call.

-- name: GetAuditChainTip :one
-- Fetch the most recent row_hash for a tenant's chain, or the platform chain's
-- when tenant_id is NULL. Called by Record() inside the caller's transaction to
-- chain the next row. One branch per kind of chain, the other always empty, so
-- each is an index scan of idx_audit_chain_tip: IS NOT DISTINCT FROM can't use
-- an index and read the whole table on every audited action.
(SELECT o.row_hash FROM audit.events o
 WHERE o.tenant_id = @tenant_id AND o.row_hash IS NOT NULL
 ORDER BY o.created_at DESC, o.id DESC LIMIT 1)
UNION ALL
(SELECT p.row_hash FROM audit.events p
 WHERE @tenant_id::uuid IS NULL AND p.tenant_id IS NULL AND p.row_hash IS NOT NULL
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
    metadata, created_at, prev_hash, row_hash
) VALUES (
    @id, @tenant_id, @actor_user_id, @actor_type, @action,
    @resource_type, @resource_id, NULLIF(@ip, '')::inet, @user_agent, @request_id,
    @metadata, @created_at, @prev_hash, @row_hash
);

-- name: ListAuditEventsForVerify :many
-- Walk the chain in chronological insert order for hash-chain verification,
-- one page after (after_created_at, after_id) at a time: a tenant's chain, or
-- the platform's when tenant_id is NULL, each branch an index scan (see
-- GetAuditChainTip). Only rows with non-NULL hashes (post-hash-chain migration)
-- are returned. COALESCE on optional fields ensures the canonical bytes match
-- what Record wrote at insert time regardless of how Postgres stored the values.
(SELECT o.id, o.tenant_id, o.actor_user_id, o.actor_type, o.action,
        o.resource_type, o.resource_id,
        COALESCE(host(o.ip), '') AS ip,
        COALESCE(o.user_agent, '') AS user_agent,
        COALESCE(o.request_id, '') AS request_id,
        o.metadata,
        o.created_at,
        o.prev_hash, o.row_hash
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
        p.prev_hash, p.row_hash
 FROM audit.events p
 WHERE @tenant_id::uuid IS NULL AND p.tenant_id IS NULL AND p.row_hash IS NOT NULL
   AND (p.created_at, p.id) > (@after_created_at::timestamptz, @after_id::uuid)
 ORDER BY p.created_at ASC, p.id ASC
 LIMIT @page_size)
ORDER BY created_at ASC, id ASC;

-- name: ListAuditChainTenants :many
-- Every organisation with a hash chain, for the scheduled verification of all
-- of them (the platform chain, NULL tenant_id, is verified separately).
SELECT DISTINCT tenant_id FROM audit.events
WHERE tenant_id IS NOT NULL AND row_hash IS NOT NULL
ORDER BY tenant_id;

-- name: InsertAuditVerificationRun :exec
-- Store one scheduled verification of every chain, as evidence.
INSERT INTO platform.audit_verification_runs (
    id, started_at, finished_at, tenants_walked, rows_checked, outcome,
    broken_tenant_id, first_broken_link, broken_reason, error
) VALUES (
    @id, @started_at, @finished_at, @tenants_walked, @rows_checked, @outcome,
    sqlc.narg(broken_tenant_id), sqlc.narg(first_broken_link), sqlc.narg(broken_reason), sqlc.narg(error)
);

-- name: LastIntactAuditVerification :one
-- When a scheduled verification last found every chain intact (0: never).
SELECT COALESCE(extract(epoch FROM max(finished_at)), 0)::float8 AS at
FROM platform.audit_verification_runs WHERE outcome = 'intact';
