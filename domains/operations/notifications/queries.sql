-- Queries for the notifications domain.
-- Static queries against auth.notifications live here and are compiled by
-- sqlc into ./dbgen. There are no dynamic queries in this domain.

-- name: InsertNotification :exec
INSERT INTO auth.notifications (user_id, tenant_id, kind, title, description, href)
VALUES (@user_id, @tenant_id, @kind, @title, @description, @href);

-- name: ListNotifications :many
SELECT id, kind, title, description, href, created_at, read_at
FROM auth.notifications
WHERE user_id = @user_id
ORDER BY created_at DESC
LIMIT @row_limit;

-- name: CountUnreadNotifications :one
SELECT COUNT(*)
FROM auth.notifications
WHERE user_id = @user_id AND read_at IS NULL;

-- name: MarkAllNotificationsRead :exec
UPDATE auth.notifications
SET read_at = NOW()
WHERE user_id = @user_id AND read_at IS NULL;
