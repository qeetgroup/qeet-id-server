-- Queries for the webhooks domain.
-- Create and Disable accept a pgx.Tx from the handler (audit sharing);
-- they are called via q.WithTx(tx). Dispatcher (tick) queries are also
-- static and included here.

-- Each subscription comes with its last delivery, and how many of its
-- deliveries are pending (none tried yet; held while it is disabled),
-- retrying and given up.
-- name: ListWebhookSubscriptions :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT s.id, s.organization_id, s.url, s.events, s.disabled_at, s.disabled_reason, s.failing_since, s.previous_secret_expires_at, s.created_at,
       (SELECT d.delivered_at FROM organization.webhook_deliveries d WHERE d.subscription_id = s.id AND d.delivered_at IS NOT NULL
        ORDER BY d.delivered_at DESC LIMIT 1) AS last_delivered_at,
       (SELECT d.status_code FROM organization.webhook_deliveries d WHERE d.subscription_id = s.id AND d.status_code IS NOT NULL
        ORDER BY COALESCE(d.delivered_at, d.dead_at, d.next_attempt_at) DESC LIMIT 1) AS last_status_code,
       (SELECT count(*) FROM organization.webhook_deliveries d WHERE d.subscription_id = s.id
        AND d.delivered_at IS NULL AND d.dead_at IS NULL AND d.attempt = 0)::int AS pending,
       (SELECT count(*) FROM organization.webhook_deliveries d WHERE d.subscription_id = s.id
        AND d.delivered_at IS NULL AND d.dead_at IS NULL AND d.attempt > 0)::int AS retrying,
       (SELECT count(*) FROM organization.webhook_deliveries d WHERE d.subscription_id = s.id AND d.dead_at IS NOT NULL)::int AS gave_up,
       s.disabled_by
FROM organization.webhook_subscriptions s
WHERE s.organization_id = @organization_id ORDER BY s.created_at DESC
LIMIT 1001;

-- name: GetWebhookSubscription :one
SELECT s.id, s.organization_id, s.url, s.events, s.disabled_at, s.disabled_reason, s.failing_since, s.previous_secret_expires_at, s.created_at,
       (SELECT d.delivered_at FROM organization.webhook_deliveries d WHERE d.subscription_id = s.id AND d.delivered_at IS NOT NULL
        ORDER BY d.delivered_at DESC LIMIT 1) AS last_delivered_at,
       (SELECT d.status_code FROM organization.webhook_deliveries d WHERE d.subscription_id = s.id AND d.status_code IS NOT NULL
        ORDER BY COALESCE(d.delivered_at, d.dead_at, d.next_attempt_at) DESC LIMIT 1) AS last_status_code,
       (SELECT count(*) FROM organization.webhook_deliveries d WHERE d.subscription_id = s.id
        AND d.delivered_at IS NULL AND d.dead_at IS NULL AND d.attempt = 0)::int AS pending,
       (SELECT count(*) FROM organization.webhook_deliveries d WHERE d.subscription_id = s.id
        AND d.delivered_at IS NULL AND d.dead_at IS NULL AND d.attempt > 0)::int AS retrying,
       (SELECT count(*) FROM organization.webhook_deliveries d WHERE d.subscription_id = s.id AND d.dead_at IS NOT NULL)::int AS gave_up,
       s.disabled_by
FROM organization.webhook_subscriptions s WHERE s.id = @id AND s.organization_id = @organization_id;

-- name: UpdateWebhookSubscription :one
UPDATE organization.webhook_subscriptions
SET url = COALESCE(sqlc.narg('url'), url), events = COALESCE(sqlc.narg('events')::text[], events)
WHERE id = @id AND organization_id = @organization_id
RETURNING url, events;

-- DisableWebhookSubscription marks the subscription disabled by an
-- administrator. RETURNING organization_id and url for the audit row.
-- name: DisableWebhookSubscription :one
UPDATE organization.webhook_subscriptions SET disabled_at = NOW(), disabled_reason = 'disabled', disabled_by = sqlc.narg('disabled_by')
WHERE id = @id AND organization_id = @organization_id AND disabled_at IS NULL
RETURNING organization_id, url;

-- EnableWebhookSubscription turns the subscription back on, however it was
-- disabled, with its failures forgotten. RETURNING url for the audit row.
-- name: EnableWebhookSubscription :one
UPDATE organization.webhook_subscriptions SET disabled_at = NULL, disabled_reason = NULL, failing_since = NULL, disabled_by = NULL
WHERE id = @id AND organization_id = @organization_id
RETURNING url;

-- LockWebhookSecret reads the subscription's signing secret for a rotation.
-- name: LockWebhookSecret :one
SELECT secret_ct, secret_nonce FROM organization.webhook_subscriptions
WHERE id = @id AND organization_id = @organization_id
FOR UPDATE;

-- RotateWebhookSecret makes the new secret current and keeps the old one,
-- signing alongside it, until previous_expires_at.
-- name: RotateWebhookSecret :exec
UPDATE organization.webhook_subscriptions
SET secret_ct = @secret_ct, secret_nonce = @secret_nonce,
    previous_secret_ct = @previous_ct, previous_secret_nonce = @previous_nonce,
    previous_secret_expires_at = @previous_expires_at
WHERE id = @id AND organization_id = @organization_id;

-- ListWebhookManagers returns the organization's active members who may
-- manage its webhooks (webhook.write, held directly or through a group).
-- name: ListWebhookManagers :many
SELECT u.id FROM account.users u
WHERE u.status = 'active' AND u.deleted_at IS NULL AND u.id IN (
    SELECT ur.user_id FROM rbac.user_roles ur
    JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE ur.organization_id = @organization_id AND p.key = 'webhook.write'
    UNION
    SELECT gm.user_id FROM organization.group_members gm
    JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
    JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE gm.organization_id = @organization_id AND p.key = 'webhook.write'
)
ORDER BY u.id;

-- ListWebhookDeliveries returns a page of a subscription's deliveries, newest
-- first, after the cursor, of a status when given: delivered, pending (not
-- tried yet), retrying or dead. Organization-scoped via the subscription join.
-- name: ListWebhookDeliveries :many
SELECT d.id, d.event_type, d.attempt, d.status_code, d.error,
       d.payload::text, d.response_body, d.delivered_at, d.next_attempt_at, d.dead_at, d.created_at
FROM organization.webhook_deliveries d
JOIN organization.webhook_subscriptions sub ON sub.id = d.subscription_id
WHERE d.subscription_id = @subscription_id AND sub.organization_id = @organization_id
  AND (sqlc.narg('status')::text IS NULL
       OR (sqlc.narg('status') = 'delivered' AND d.delivered_at IS NOT NULL)
       OR (sqlc.narg('status') = 'dead' AND d.dead_at IS NOT NULL)
       OR (sqlc.narg('status') = 'pending' AND d.delivered_at IS NULL AND d.dead_at IS NULL AND d.attempt = 0)
       OR (sqlc.narg('status') = 'retrying' AND d.delivered_at IS NULL AND d.dead_at IS NULL AND d.attempt > 0))
  AND (sqlc.narg('before_ts')::timestamptz IS NULL OR d.created_at < sqlc.narg('before_ts')
       OR (d.created_at = sqlc.narg('before_ts') AND d.id < sqlc.narg('before_id')::uuid))
ORDER BY d.created_at DESC, d.id DESC
LIMIT @row_limit;

-- RetryDeadDeliveries re-queues, with a fresh budget of attempts, up to
-- row_limit of a subscription's given-up deliveries.
-- name: RetryDeadDeliveries :execrows
UPDATE organization.webhook_deliveries d
SET delivered_at = NULL, dead_at = NULL, error = NULL, next_attempt_at = NOW(), attempt = 0,
    lease_owner = NULL, lease_until = NULL
WHERE d.id IN (
    SELECT dd.id FROM organization.webhook_deliveries dd
    JOIN organization.webhook_subscriptions sub ON sub.id = dd.subscription_id
    WHERE dd.subscription_id = @subscription_id AND sub.organization_id = @organization_id AND dd.dead_at IS NOT NULL
    LIMIT @row_limit);

-- name: InsertDeliveryAttempt :exec
INSERT INTO organization.webhook_delivery_attempts (organization_id, delivery_id, status_code, duration_ms, error)
VALUES (@organization_id, @delivery_id, sqlc.narg('status_code'), @duration_ms, sqlc.narg('error'));

-- name: ListDeliveryAttempts :many
-- One of the organization's deliveries' attempts, oldest first.
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT a.attempted_at, a.status_code, a.duration_ms, a.error
FROM organization.webhook_delivery_attempts a
JOIN organization.webhook_deliveries d ON d.id = a.delivery_id
JOIN organization.webhook_subscriptions sub ON sub.id = d.subscription_id
WHERE a.delivery_id = @delivery_id AND d.subscription_id = @subscription_id AND a.organization_id = @organization_id AND sub.organization_id = @organization_id
ORDER BY a.attempted_at
LIMIT 1001;

-- name: RetryWebhookDelivery :execrows
UPDATE organization.webhook_deliveries d
SET delivered_at = NULL, dead_at = NULL, error = NULL, next_attempt_at = NOW()
FROM organization.webhook_subscriptions sub
WHERE d.id = @delivery_id AND d.subscription_id = sub.id AND sub.organization_id = @organization_id;

-- GetSubscriptionsForEvent returns subscription IDs for Enqueue: the active
-- subscriptions that name the event type.
-- name: GetSubscriptionsForEvent :many
SELECT id FROM organization.webhook_subscriptions
WHERE organization_id = @organization_id AND disabled_at IS NULL
  AND @event_type::text = ANY(events);

-- InsertDelivery queues an event for a subscription, once: the same event
-- again is a no-op.
-- name: InsertDelivery :exec
INSERT INTO organization.webhook_deliveries (subscription_id, event_id, event_type, payload, next_attempt_at)
VALUES (@subscription_id, @event_id, @event_type, @payload, NOW())
ON CONFLICT (subscription_id, event_id) DO NOTHING;

-- name: MarkDeliverySucceeded :exec
UPDATE organization.webhook_deliveries
SET delivered_at = NOW(), status_code = @status_code, response_body = @response_body,
    attempt = attempt + 1, error = NULL
WHERE id = @id;

-- name: DeadLetterDelivery :exec
UPDATE organization.webhook_deliveries
SET attempt = attempt + 1, status_code = @status_code, response_body = @response_body,
    error = @error, dead_at = NOW()
WHERE id = @id;

-- name: ScheduleDeliveryRetry :exec
UPDATE organization.webhook_deliveries
SET attempt = attempt + 1,
    status_code = @status_code,
    response_body = @response_body,
    error = @error,
    next_attempt_at = @next_attempt_at
WHERE id = @id;
