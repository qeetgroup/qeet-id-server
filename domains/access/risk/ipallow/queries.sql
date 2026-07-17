-- Queries for the risk/ipallow domain.
-- All queries are static and compiled by sqlc into ./dbgen.

-- name: ListIPRules :many
SELECT id, tenant_id, cidr, label, action, created_at
FROM tenant.ip_rules WHERE tenant_id = $1 ORDER BY action, created_at;

-- name: GetIPRulesEnabled :one
SELECT enabled FROM tenant.ip_rules_config WHERE tenant_id = $1;

-- name: SetIPRulesEnabled :exec
INSERT INTO tenant.ip_rules_config (tenant_id, enabled, updated_at)
VALUES ($1, $2, NOW())
ON CONFLICT (tenant_id) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = NOW();

-- name: InsertIPRule :one
INSERT INTO tenant.ip_rules (tenant_id, cidr, label, action)
VALUES ($1, $2, $3, $4)
RETURNING id, tenant_id, cidr, label, action, created_at;

-- name: DeleteIPRule :execrows
DELETE FROM tenant.ip_rules WHERE id = $1 AND tenant_id = $2;
