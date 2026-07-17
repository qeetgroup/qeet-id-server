-- Queries for the webhooks domain.
-- Create and Disable accept a pgx.Tx from the handler (audit sharing);
-- they are called via q.WithTx(tx). Dispatcher (tick) queries are also
-- static and included here.

-- name: CreateWebhookSubscription :one
INSERT INTO tenant.webhook_subscriptions (tenant_id, url, secret, events)
VALUES (@tenant_id, @url, @secret, @events)
RETURNING id, tenant_id, url, events, disabled_at, created_at;

-- name: ListWebhookSubscriptions :many
SELECT id, tenant_id, url, events, disabled_at, created_at
FROM tenant.webhook_subscriptions
WHERE tenant_id = $1 ORDER BY created_at DESC;

-- name: GetWebhookSubscription :one
SELECT id, tenant_id, url, events, disabled_at, created_at
FROM tenant.webhook_subscriptions WHERE id = @id AND tenant_id = @tenant_id;

-- DisableWebhookSubscription marks the subscription disabled. RETURNING
-- tenant_id and url for the audit row.
-- name: DisableWebhookSubscription :one
UPDATE tenant.webhook_subscriptions SET disabled_at = NOW()
WHERE id = @id AND tenant_id = @tenant_id AND disabled_at IS NULL
RETURNING tenant_id, url;

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

-- GetSubscriptionsForEvent returns subscription IDs for Enqueue: active
-- subscriptions matching the event type (or subscribed to all events).
-- name: GetSubscriptionsForEvent :many
SELECT id FROM tenant.webhook_subscriptions
WHERE tenant_id = @tenant_id AND disabled_at IS NULL
  AND (@event_type::text = ANY(events) OR events = '{}'::text[]);

-- name: InsertDelivery :exec
INSERT INTO tenant.webhook_deliveries (subscription_id, event_type, payload, next_attempt_at)
VALUES (@subscription_id, @event_type, @payload, NOW());

-- Dispatcher queries (tick): fetch due deliveries then update outcome.

-- name: GetDueDeliveries :many
SELECT d.id, d.subscription_id, d.event_type, d.payload, d.attempt, sub.url, sub.secret
FROM tenant.webhook_deliveries d
JOIN tenant.webhook_subscriptions sub ON sub.id = d.subscription_id
WHERE d.delivered_at IS NULL
  AND d.dead_at IS NULL
  AND d.next_attempt_at <= NOW()
  AND sub.disabled_at IS NULL
ORDER BY d.created_at
LIMIT 20
FOR UPDATE SKIP LOCKED;

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
