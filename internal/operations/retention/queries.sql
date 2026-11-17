-- Queries for the retention domain.
-- Static queries against organization.retention_policy and account.users live here
-- and are compiled by sqlc into ./dbgen.

-- name: GetRetentionPolicy :one
SELECT p.deleted_users_enabled, p.deleted_users_days, p.updated_at, p.updated_by, u.email AS updated_by_email
FROM organization.retention_policy p
LEFT JOIN account.users u ON u.id = p.updated_by
WHERE p.organization_id = $1;

-- Upsert an organization's retention policy and return the stored values.
-- name: UpsertRetentionPolicy :one
INSERT INTO organization.retention_policy (organization_id, deleted_users_enabled, deleted_users_days, updated_at, updated_by)
VALUES ($1, $2, $3, NOW(), sqlc.narg('updated_by'))
ON CONFLICT (organization_id) DO UPDATE SET
    deleted_users_enabled = EXCLUDED.deleted_users_enabled,
    deleted_users_days    = EXCLUDED.deleted_users_days,
    updated_at            = NOW(),
    updated_by            = EXCLUDED.updated_by
RETURNING deleted_users_enabled, deleted_users_days, updated_at;

-- Count soft-deleted users older than `days` days for a given organization.
-- The days value is clamped to [1,3650] by the caller before it reaches here.
-- name: CountRipeDeletedUsers :one
SELECT count(*)
FROM account.users
WHERE organization_id = $1
  AND deleted_at IS NOT NULL
  AND deleted_at < NOW() - make_interval(days => $2);

-- ListRipeDeletedUsers lists, in ID order after @after, at most @max_rows of
-- the organization's soft-deleted users older than @days days.
-- name: ListRipeDeletedUsers :many
SELECT id FROM account.users
WHERE organization_id = @organization_id
  AND deleted_at IS NOT NULL
  AND deleted_at < NOW() - make_interval(days => @days)
  AND id > @after
ORDER BY id
LIMIT @max_rows;

-- PurgeRipeDeletedUser permanently removes one of the organization's soft-deleted
-- users older than @days days.
-- name: PurgeRipeDeletedUser :execrows
DELETE FROM account.users
WHERE id = @id AND organization_id = @organization_id
  AND deleted_at IS NOT NULL
  AND deleted_at < NOW() - make_interval(days => @days);

-- name: ListEnabledRetentionPolicies :many
SELECT organization_id, deleted_users_days
FROM organization.retention_policy
WHERE deleted_users_enabled = TRUE;
