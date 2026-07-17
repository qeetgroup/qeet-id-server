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
