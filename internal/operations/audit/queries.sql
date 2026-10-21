-- Queries for the audit domain.
--
-- The hash-chained append-only audit log.  Static queries are here; dynamic
-- ones stay hand-written in the respective .go files:
--   - Reader.List (http.go): dynamic WHERE clause with optional action, resource
--     type, actor, free-text search, and cursor filters.
--   - Record advisory-lock call (audit.go): pg_advisory_xact_lock is a
--     void-returning side-effect function; it stays as a raw tx.Exec call.

-- name: GetAuditChainTip :one
-- Fetch the most recent row_hash for a tenant's (or the platform) chain.
-- Called by Record() inside the caller's transaction to chain the next row.
-- tenant_id = NULL means the platform chain (NULL IS NOT DISTINCT FROM NULL).
SELECT row_hash FROM audit.events
WHERE tenant_id IS NOT DISTINCT FROM @tenant_id
  AND row_hash IS NOT NULL
ORDER BY created_at DESC, id DESC
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
-- Walk the chain in chronological insert order for hash-chain verification.
-- Only rows with non-NULL hashes (post-hash-chain migration) are returned.
-- COALESCE on optional fields ensures the canonical bytes match what Record
-- wrote at insert time regardless of how Postgres stored the values.
SELECT id, tenant_id, actor_user_id, actor_type, action,
       resource_type, resource_id,
       COALESCE(host(ip), '') AS ip,
       COALESCE(user_agent, '') AS user_agent,
       COALESCE(request_id, '') AS request_id,
       metadata,
       created_at,
       prev_hash, row_hash
FROM audit.events
WHERE tenant_id IS NOT DISTINCT FROM @tenant_id
  AND row_hash IS NOT NULL
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
