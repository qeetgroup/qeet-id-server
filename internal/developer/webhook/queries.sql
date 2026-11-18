-- Queries for the webhooks domain, the dispatcher's included.

-- name: CreateWebhookSubscription :one
INSERT INTO organization.webhook_subscriptions (id, organization_id, url, secret_ct, secret_nonce, events, created_by)
VALUES (@id, @organization_id, @url, @secret_ct, @secret_nonce, @events, sqlc.narg('created_by'))
RETURNING id, organization_id, url, events, disabled_at, created_at;

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
-- administrator, returning its url for the audit row.
-- name: DisableWebhookSubscription :one
UPDATE organization.webhook_subscriptions SET disabled_at = NOW(), disabled_reason = 'disabled', disabled_by = sqlc.narg('disabled_by')
WHERE id = @id AND organization_id = @organization_id AND disabled_at IS NULL
RETURNING url;

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

-- RetryWebhookDelivery re-queues one of a subscription's deliveries that no
-- dispatcher holds, for now. One that had finished, delivered or given up,
-- starts a fresh budget of attempts; one still retrying keeps its count.
-- name: RetryWebhookDelivery :execrows
UPDATE organization.webhook_deliveries AS delivery
SET delivered_at = NULL, dead_at = NULL, error = NULL, next_attempt_at = NOW(),
    lease_owner = NULL, lease_until = NULL,
    attempt = CASE WHEN delivery.dead_at IS NOT NULL OR delivery.delivered_at IS NOT NULL
                   THEN 0 ELSE delivery.attempt END
FROM organization.webhook_subscriptions AS subscription
WHERE delivery.id = @delivery_id AND delivery.subscription_id = subscription.id
  AND subscription.id = @subscription_id AND subscription.organization_id = @organization_id
  AND (delivery.lease_until IS NULL OR delivery.lease_until <= NOW());

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

-- ClaimDueDeliveries leases to lease_owner, until lease_until, up to 20 due
-- deliveries of enabled subscriptions that no other dispatcher holds, oldest
-- first, with what sending each takes. It works across every organization.
-- name: ClaimDueDeliveries :many
WITH candidates AS (
    SELECT delivery.id
    FROM organization.webhook_deliveries AS delivery
    JOIN organization.webhook_subscriptions AS subscription ON subscription.id = delivery.subscription_id
    WHERE delivery.delivered_at IS NULL AND delivery.dead_at IS NULL
      AND delivery.next_attempt_at <= NOW()
      AND (delivery.lease_until IS NULL OR delivery.lease_until <= NOW())
      AND subscription.disabled_at IS NULL
    ORDER BY delivery.created_at
    LIMIT 20
    FOR UPDATE OF delivery SKIP LOCKED
)
UPDATE organization.webhook_deliveries AS delivery
SET lease_owner = @lease_owner::uuid, lease_until = @lease_until::timestamptz
FROM candidates, organization.webhook_subscriptions AS subscription
WHERE delivery.id = candidates.id AND subscription.id = delivery.subscription_id
RETURNING delivery.id, delivery.subscription_id, delivery.event_type, delivery.payload, delivery.attempt,
          subscription.organization_id, subscription.url, subscription.secret_ct, subscription.secret_nonce,
          subscription.previous_secret_ct, subscription.previous_secret_nonce, subscription.previous_secret_expires_at;

-- DeadLetterUnsent gives up, without sending it, a delivery lease_owner holds,
-- with why, releasing its lease. The queries after it end a delivery's attempt
-- the same way.
-- name: DeadLetterUnsent :exec
UPDATE organization.webhook_deliveries
SET error = @error, dead_at = NOW(), lease_owner = NULL, lease_until = NULL
WHERE id = @id AND lease_owner = @lease_owner::uuid;

-- name: MarkDeliverySucceeded :exec
UPDATE organization.webhook_deliveries
SET delivered_at = NOW(), status_code = sqlc.narg('status_code'), response_body = sqlc.narg('response_body'),
    attempt = attempt + 1, error = NULL,
    lease_owner = NULL, lease_until = NULL
WHERE id = @id AND lease_owner = @lease_owner::uuid;

-- name: DeadLetterDelivery :exec
UPDATE organization.webhook_deliveries
SET attempt = attempt + 1, status_code = sqlc.narg('status_code'), response_body = sqlc.narg('response_body'),
    error = sqlc.narg('error'), dead_at = NOW(), lease_owner = NULL, lease_until = NULL
WHERE id = @id AND lease_owner = @lease_owner::uuid;

-- name: ScheduleDeliveryRetry :exec
UPDATE organization.webhook_deliveries
SET attempt = attempt + 1, status_code = sqlc.narg('status_code'), response_body = sqlc.narg('response_body'),
    error = sqlc.narg('error'), next_attempt_at = @next_attempt_at::timestamptz,
    lease_owner = NULL, lease_until = NULL
WHERE id = @id AND lease_owner = @lease_owner::uuid;

-- ClearSubscriptionFailing forgets a subscription's failures after a delivery
-- to it succeeded.
-- name: ClearSubscriptionFailing :exec
UPDATE organization.webhook_subscriptions SET failing_since = NULL
WHERE id = @id AND organization_id = @organization_id AND failing_since IS NOT NULL;

-- NoteSubscriptionFailure marks an enabled subscription failing from now,
-- unless it already was, and disables it as failing once it has been failing
-- since disable_before. No row: it is disabled already.
-- name: NoteSubscriptionFailure :one
UPDATE organization.webhook_subscriptions
SET failing_since = COALESCE(failing_since, NOW()),
    disabled_at = CASE WHEN failing_since <= @disable_before::timestamptz THEN NOW() END,
    disabled_reason = CASE WHEN failing_since <= @disable_before::timestamptz THEN 'failing' END
WHERE id = @id AND organization_id = @organization_id AND disabled_at IS NULL
RETURNING url, failing_since, (disabled_at IS NOT NULL)::bool AS disabled;
