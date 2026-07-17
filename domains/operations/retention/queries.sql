-- Queries for the retention domain.
-- Static queries against tenant.retention_policy and "user".users live here
-- and are compiled by sqlc into ./dbgen.

-- name: GetRetentionPolicy :one
SELECT deleted_users_enabled, deleted_users_days
FROM tenant.retention_policy
WHERE tenant_id = $1;

-- Upsert a tenant's retention policy and return the stored values.
-- name: UpsertRetentionPolicy :one
INSERT INTO tenant.retention_policy (tenant_id, deleted_users_enabled, deleted_users_days, updated_at)
VALUES ($1, $2, $3, NOW())
ON CONFLICT (tenant_id) DO UPDATE SET
    deleted_users_enabled = EXCLUDED.deleted_users_enabled,
    deleted_users_days    = EXCLUDED.deleted_users_days,
    updated_at            = NOW()
RETURNING deleted_users_enabled, deleted_users_days;

-- Count soft-deleted users older than `days` days for a given tenant.
-- The days value is clamped to [1,3650] by the caller before it reaches here.
-- name: CountRipeDeletedUsers :one
SELECT count(*)
FROM "user".users
WHERE tenant_id = $1
  AND deleted_at IS NOT NULL
  AND deleted_at < NOW() - make_interval(days => $2);

-- Permanently remove soft-deleted users older than `days` days.
-- Returns the number of rows deleted via :execrows.
-- name: PurgeRipeDeletedUsers :execrows
DELETE FROM "user".users
WHERE tenant_id = $1
  AND deleted_at IS NOT NULL
  AND deleted_at < NOW() - make_interval(days => $2);

-- name: ListEnabledRetentionPolicies :many
SELECT tenant_id, deleted_users_days
FROM tenant.retention_policy
WHERE deleted_users_enabled = TRUE;
