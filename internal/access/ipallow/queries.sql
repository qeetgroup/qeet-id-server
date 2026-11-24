-- Queries for the risk/ipallow domain.
-- All queries are static and compiled by sqlc into ./dbgen.

-- name: ListIPRules :many
SELECT id, organization_id, cidr, label, action, created_at
FROM organization.ip_rules WHERE organization_id = $1 ORDER BY action, created_at;

-- name: GetIPRulesEnabled :one
SELECT enabled FROM organization.ip_rules_config WHERE organization_id = $1;

-- name: SetIPRulesEnabled :exec
INSERT INTO organization.ip_rules_config (organization_id, enabled, updated_at)
VALUES ($1, $2, NOW())
ON CONFLICT (organization_id) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = NOW();

-- name: InsertIPRule :one
INSERT INTO organization.ip_rules (organization_id, cidr, label, action)
VALUES ($1, $2, $3, $4)
RETURNING id, organization_id, cidr, label, action, created_at;

-- name: DeleteIPRule :one
DELETE FROM organization.ip_rules WHERE id = $1 AND organization_id = $2
RETURNING id, organization_id, cidr, label, action, created_at;
