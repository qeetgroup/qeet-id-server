-- Queries for the retention domain.
-- Static queries against tenant.retention_policy and "user".users live here
-- and are compiled by sqlc into ./dbgen.

-- name: GetRetentionPolicy :one
SELECT p.deleted_users_enabled, p.deleted_users_days, p.updated_at, p.updated_by, u.email AS updated_by_email
FROM tenant.retention_policy p
LEFT JOIN "user".users u ON u.id = p.updated_by
WHERE p.tenant_id = $1;

-- Upsert a tenant's retention policy and return the stored values.
-- name: UpsertRetentionPolicy :one
INSERT INTO tenant.retention_policy (tenant_id, deleted_users_enabled, deleted_users_days, updated_at, updated_by)
VALUES ($1, $2, $3, NOW(), sqlc.narg('updated_by'))
ON CONFLICT (tenant_id) DO UPDATE SET
    deleted_users_enabled = EXCLUDED.deleted_users_enabled,
    deleted_users_days    = EXCLUDED.deleted_users_days,
    updated_at            = NOW(),
    updated_by            = EXCLUDED.updated_by
RETURNING deleted_users_enabled, deleted_users_days, updated_at;

-- Count soft-deleted users older than `days` days for a given tenant.
-- The days value is clamped to [1,3650] by the caller before it reaches here.
-- name: CountRipeDeletedUsers :one
SELECT count(*)
FROM "user".users
WHERE tenant_id = $1
  AND deleted_at IS NOT NULL
  AND deleted_at < NOW() - make_interval(days => $2);

-- ListRipeDeletedUsers lists, in ID order after @after, at most @max_rows of
-- the tenant's soft-deleted users older than @days days.
-- name: ListRipeDeletedUsers :many
SELECT id FROM "user".users
WHERE tenant_id = @tenant_id
  AND deleted_at IS NOT NULL
  AND deleted_at < NOW() - make_interval(days => @days)
  AND id > @after
ORDER BY id
LIMIT @max_rows;

-- PurgeRipeDeletedUser permanently removes one of the tenant's soft-deleted
-- users older than @days days.
-- name: PurgeRipeDeletedUser :execrows
DELETE FROM "user".users
WHERE id = @id AND tenant_id = @tenant_id
  AND deleted_at IS NOT NULL
  AND deleted_at < NOW() - make_interval(days => @days);

-- name: ListEnabledRetentionPolicies :many
SELECT tenant_id, deleted_users_days
FROM tenant.retention_policy
WHERE deleted_users_enabled = TRUE;
