-- Queries for the webhooks domain.
-- Create and Disable accept a pgx.Tx from the handler (audit sharing);
-- they are called via q.WithTx(tx). Dispatcher (tick) queries are also
-- static and included here.

-- name: ListWebhookSubscriptions :many
SELECT id, tenant_id, url, events, disabled_at, disabled_reason, failing_since, previous_secret_expires_at, created_at
FROM tenant.webhook_subscriptions
WHERE tenant_id = $1 ORDER BY created_at DESC;

-- name: GetWebhookSubscription :one
SELECT id, tenant_id, url, events, disabled_at, disabled_reason, failing_since, previous_secret_expires_at, created_at
FROM tenant.webhook_subscriptions WHERE id = @id AND tenant_id = @tenant_id;

-- DisableWebhookSubscription marks the subscription disabled by an
-- administrator. RETURNING tenant_id and url for the audit row.
-- name: DisableWebhookSubscription :one
UPDATE tenant.webhook_subscriptions SET disabled_at = NOW(), disabled_reason = 'disabled'
WHERE id = @id AND tenant_id = @tenant_id AND disabled_at IS NULL
RETURNING tenant_id, url;

-- EnableWebhookSubscription turns the subscription back on, however it was
-- disabled, with its failures forgotten. RETURNING url for the audit row.
-- name: EnableWebhookSubscription :one
UPDATE tenant.webhook_subscriptions SET disabled_at = NULL, disabled_reason = NULL, failing_since = NULL
WHERE id = @id AND tenant_id = @tenant_id
RETURNING url;

-- LockWebhookSecret reads the subscription's signing secret for a rotation.
-- name: LockWebhookSecret :one
SELECT secret, secret_ct, secret_nonce FROM tenant.webhook_subscriptions
WHERE id = @id AND tenant_id = @tenant_id
FOR UPDATE;

-- RotateWebhookSecret makes the new secret current and keeps the old one,
-- signing alongside it, until previous_expires_at.
-- name: RotateWebhookSecret :exec
UPDATE tenant.webhook_subscriptions
SET secret = '', secret_ct = @secret_ct, secret_nonce = @secret_nonce, encryption_version = 1,
    previous_secret_ct = @previous_ct, previous_secret_nonce = @previous_nonce,
    previous_secret_expires_at = @previous_expires_at
WHERE id = @id AND tenant_id = @tenant_id;

-- ListWebhookManagers returns the organisation's active members who may
-- manage its webhooks (webhook.write, held directly or through a group).
-- name: ListWebhookManagers :many
SELECT u.id FROM "user".users u
WHERE u.status = 'active' AND u.deleted_at IS NULL AND u.id IN (
    SELECT ur.user_id FROM rbac.user_roles ur
    JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE ur.tenant_id = @tenant_id AND p.key = 'webhook.write'
    UNION
    SELECT gm.user_id FROM tenant.group_members gm
    JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
    JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE gm.tenant_id = @tenant_id AND p.key = 'webhook.write'
)
ORDER BY u.id;

-- ListWebhookDeliveries returns recent deliveries for a subscription, newest
-- first. Tenant-scoped via the subscription join.
-- name: ListWebhookDeliveries :many
SELECT d.id, d.event_type, d.attempt, d.status_code, d.error,
       d.payload::text, d.response_body, d.delivered_at, d.next_attempt_at, d.dead_at, d.created_at
FROM tenant.webhook_deliveries d
JOIN tenant.webhook_subscriptions sub ON sub.id = d.subscription_id
WHERE d.subscription_id = @subscription_id AND sub.tenant_id = @tenant_id
ORDER BY d.created_at DESC
LIMIT @row_limit;

-- name: RetryWebhookDelivery :execrows
UPDATE tenant.webhook_deliveries d
SET delivered_at = NULL, dead_at = NULL, error = NULL, next_attempt_at = NOW()
FROM tenant.webhook_subscriptions sub
WHERE d.id = @delivery_id AND d.subscription_id = sub.id AND sub.tenant_id = @tenant_id;

-- GetSubscriptionsForEvent returns subscription IDs for Enqueue: the active
-- subscriptions that name the event type.
-- name: GetSubscriptionsForEvent :many
SELECT id FROM tenant.webhook_subscriptions
WHERE tenant_id = @tenant_id AND disabled_at IS NULL
  AND @event_type::text = ANY(events);

-- InsertDelivery queues an event for a subscription, once: the same event
-- again is a no-op.
-- name: InsertDelivery :exec
INSERT INTO tenant.webhook_deliveries (subscription_id, event_id, event_type, payload, next_attempt_at)
VALUES (@subscription_id, @event_id, @event_type, @payload, NOW())
ON CONFLICT (subscription_id, event_id) DO NOTHING;

-- name: MarkDeliverySucceeded :exec
UPDATE tenant.webhook_deliveries
SET delivered_at = NOW(), status_code = @status_code, response_body = @response_body,
    attempt = attempt + 1, error = NULL
WHERE id = @id;

-- name: DeadLetterDelivery :exec
UPDATE tenant.webhook_deliveries
SET attempt = attempt + 1, status_code = @status_code, response_body = @response_body,
    error = @error, dead_at = NOW()
WHERE id = @id;

-- name: ScheduleDeliveryRetry :exec
UPDATE tenant.webhook_deliveries
SET attempt = attempt + 1,
    status_code = @status_code,
    response_body = @response_body,
    error = @error,
    next_attempt_at = @next_attempt_at
WHERE id = @id;
