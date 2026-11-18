-- Queries for the directory domain, compiled by sqlc into ./dbgen. The event
-- and error lists, whose filters and breakdowns vary, stay in events.go and
-- sync_errors.go.

-- ---- Events (events.go) ----

-- name: InsertDirectoryEvent :exec
INSERT INTO organization.directory_events
    (id, organization_id, connection_id, operation, trigger_type, resource_type, resource_id, started_at,
     duration_ms, http_status, status, users_synced, groups_synced, error_code, message, category, severity,
     retry_of, reason, params, subject, user_id)
VALUES (@id, @organization_id, @connection_id, @operation, @trigger_type, @resource_type, @resource_id, @started_at,
        @duration_ms, @http_status, @status, @users_synced, @groups_synced, @error_code, @message, @category, @severity,
        sqlc.narg('retry_of'), @reason, @params, @subject, sqlc.narg('user_id'));

-- OpenConnectionFailuresExist reports whether the connection has an open
-- failure a success disproves (the directory unreachable or refusing the
-- connection's own credentials), other than the one being retried.
-- name: OpenConnectionFailuresExist :one
SELECT EXISTS (
    SELECT 1 FROM organization.directory_events
    WHERE organization_id = @organization_id AND connection_id = @connection_id AND status = 'failed'
      AND resolution = 'open' AND category IN ('connection', 'permission') AND id <> @retrying
);

-- name: ResolveConnectionFailures :many
UPDATE organization.directory_events SET resolution = 'resolved', resolved_at = NOW(), resolved_by = NULL
WHERE organization_id = @organization_id AND connection_id = @connection_id AND status = 'failed'
  AND resolution = 'open' AND category IN ('connection', 'permission') AND id <> @retrying
RETURNING id;

-- name: LatestDirectoryEvents :many
-- Each connection's latest event.
SELECT DISTINCT ON (connection_id) connection_id, status, started_at
FROM organization.directory_events
WHERE organization_id = @organization_id
ORDER BY connection_id, started_at DESC, id DESC;

-- name: LastDirectorySyncs :many
-- Each connection's latest successful sync of a user or group.
SELECT connection_id, max(started_at)::timestamptz AS synced_at
FROM organization.directory_events
WHERE organization_id = @organization_id AND status = 'success' AND resource_type <> 'connection'
GROUP BY connection_id;

-- ---- Connections (directory.go) ----

-- name: CountLDAPPeople :many
-- The people with an identity each LDAP connection signed in.
SELECT ei.connection_id::text AS connection_id, count(DISTINCT ei.user_id)::int AS people
FROM account.external_identities ei
JOIN account.users u ON u.id = ei.user_id AND u.deleted_at IS NULL
WHERE ei.organization_id = @organization_id AND ei.provider = 'ldap' AND ei.connection_id IS NOT NULL
GROUP BY ei.connection_id;

-- name: CountSCIMGroups :one
SELECT count(*)::int FROM organization.groups WHERE organization_id = @organization_id AND provisioned_via = 'scim';

-- ---- Alerts (alerts.go) ----

-- name: ListDirectoryAlerts :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, name, connection_id, threshold, enabled, user_id, created_at, last_notified_at
FROM organization.directory_alerts WHERE organization_id = @organization_id
ORDER BY created_at DESC, id
LIMIT 1001;

-- name: InsertDirectoryAlert :one
INSERT INTO organization.directory_alerts (id, organization_id, user_id, name, connection_id, threshold, enabled)
VALUES (@id, @organization_id, @user_id, @name, sqlc.narg('connection_id'), @threshold, true)
RETURNING id, name, connection_id, threshold, enabled, user_id, created_at, last_notified_at;

-- name: UpdateDirectoryAlert :one
-- Changes the fields given; with set_connection_id an empty connection_id
-- makes the alert cover every connection.
UPDATE organization.directory_alerts SET
    name = COALESCE(sqlc.narg('name'), name),
    connection_id = CASE WHEN @set_connection_id::boolean THEN NULLIF(sqlc.narg('connection_id')::text, '') ELSE connection_id END,
    threshold = COALESCE(sqlc.narg('threshold'), threshold),
    enabled = COALESCE(sqlc.narg('enabled'), enabled)
WHERE organization_id = @organization_id AND id = @id
RETURNING id, name, connection_id, threshold, enabled, user_id, created_at, last_notified_at;

-- name: DeleteDirectoryAlert :execrows
DELETE FROM organization.directory_alerts WHERE organization_id = @organization_id AND id = @id;

-- NotifyDirectoryAlerts notifies the owner of each alert on the connection
-- whose threshold the last 15 minutes' failures reached, at most once in 15
-- minutes.
-- name: NotifyDirectoryAlerts :exec
WITH notified AS (
    UPDATE organization.directory_alerts SET last_notified_at = NOW()
    WHERE organization_id = @organization_id AND enabled
      AND (connection_id IS NULL OR connection_id = @connection_id::text)
      AND (last_notified_at IS NULL OR last_notified_at < NOW() - INTERVAL '15 minutes')
      AND threshold <= (
          SELECT count(*) FROM organization.directory_events
          WHERE organization_id = @organization_id AND status = 'failed' AND started_at >= NOW() - INTERVAL '15 minutes'
            AND (directory_alerts.connection_id IS NULL OR connection_id = directory_alerts.connection_id))
    RETURNING user_id, name
)
INSERT INTO auth.notifications (user_id, organization_id, kind, title, description, href)
SELECT user_id, @organization_id, 'warning', name, @description::text, '/directory/sync-errors' FROM notified;

-- ---- Errors (sync_errors.go) ----

-- name: GetOpenDirectoryError :one
SELECT id, connection_id, operation, trigger_type, resource_type, resource_id, started_at, duration_ms, http_status,
       status, users_synced, groups_synced, error_code, message, category, severity, resolution, resolved_at,
       retry_of, reason, params, subject, user_id
FROM organization.directory_events WHERE organization_id = @organization_id AND id = @id AND status = 'failed';

-- name: LockOpenDirectoryError :one
-- NO KEY UPDATE still stops two requests settling the error, and lets a new
-- event that refers to it be inserted meanwhile.
SELECT id, connection_id, operation, trigger_type, resource_type, resource_id, started_at, duration_ms, http_status,
       status, users_synced, groups_synced, error_code, message, category, severity, resolution, resolved_at,
       retry_of, reason, params, subject, user_id
FROM organization.directory_events WHERE organization_id = @organization_id AND id = @id AND status = 'failed'
FOR NO KEY UPDATE;

-- name: SettleDirectoryError :exec
UPDATE organization.directory_events SET resolution = @resolution, resolved_at = NOW(), resolved_by = sqlc.narg('resolved_by')
WHERE organization_id = @organization_id AND id = @id;

-- name: RecentRemediations :many
-- The five errors last settled, of one connection or ('') every one.
SELECT id, connection_id, operation, trigger_type, resource_type, resource_id, started_at, duration_ms, http_status,
       status, users_synced, groups_synced, error_code, message, category, severity, resolution, resolved_at,
       retry_of, reason, params, subject, user_id
FROM organization.directory_events
WHERE organization_id = @organization_id AND resolved_at IS NOT NULL AND (@connection_id::text = '' OR connection_id = @connection_id)
ORDER BY resolved_at DESC, id DESC
LIMIT 5;

-- ---- Mappings and profiles (mapping_store.go) ----

-- name: ListDirectoryMappings :many
SELECT id, source_attribute, target_field, value_type, transform, pattern, enabled, required, version
FROM organization.directory_mappings WHERE organization_id = @organization_id AND connection_id = @connection_id
ORDER BY created_at, id;

-- name: CountDirectoryMappings :one
SELECT count(*) FROM organization.directory_mappings WHERE organization_id = @organization_id AND connection_id = @connection_id;

-- name: InsertDirectoryMapping :one
INSERT INTO organization.directory_mappings
    (id, organization_id, connection_id, source_attribute, target_field, value_type, transform, pattern, enabled, required)
VALUES (@id, @organization_id, @connection_id, @source_attribute, @target_field, @value_type, @transform, @pattern, @enabled, @required)
RETURNING id, source_attribute, target_field, value_type, transform, pattern, enabled, required, version;

-- name: UpdateDirectoryMapping :one
-- Only while the mapping is still at version.
UPDATE organization.directory_mappings SET
    source_attribute = @source_attribute, target_field = @target_field, value_type = @value_type, transform = @transform,
    pattern = @pattern, enabled = @enabled, required = @required, version = version + 1, updated_at = NOW()
WHERE organization_id = @organization_id AND connection_id = @connection_id AND id = @id AND version = @version
RETURNING id, source_attribute, target_field, value_type, transform, pattern, enabled, required, version;

-- name: DeleteDirectoryMapping :execrows
DELETE FROM organization.directory_mappings WHERE organization_id = @organization_id AND connection_id = @connection_id AND id = @id;

-- name: UpsertDirectoryProfile :exec
-- Merges profile into what the connection set on the person before; a null
-- field removes one.
INSERT INTO organization.directory_profiles (organization_id, user_id, connection_id, profile)
VALUES (@organization_id, @user_id, @connection_id, jsonb_strip_nulls(@profile::jsonb))
ON CONFLICT (organization_id, user_id, connection_id) DO UPDATE
SET profile = jsonb_strip_nulls(directory_profiles.profile || @profile::jsonb), updated_at = NOW();

-- name: SetMappedDisplayName :exec
UPDATE account.users SET display_name = @display_name, updated_at = NOW()
WHERE organization_id = @organization_id AND id = @id AND deleted_at IS NULL;

-- name: ListDirectoryProfiles :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT connection_id, profile, updated_at FROM organization.directory_profiles
WHERE organization_id = @organization_id AND user_id = @user_id
ORDER BY updated_at DESC, connection_id
LIMIT 1001;
