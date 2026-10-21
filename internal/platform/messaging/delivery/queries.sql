-- Queries for email delivery records and the suppression list.

-- name: InsertMessage :one
INSERT INTO platform.email_messages
    (tenant_id, to_hash, to_hint, template, provider, provider_message_id, status, status_reason)
VALUES (@tenant_id, @to_hash, @to_hint, @template, @provider, sqlc.narg(provider_message_id), @status, @status_reason)
RETURNING id;

-- name: ActiveSuppression :one
SELECT id, tenant_id, reason, detail, created_at
FROM platform.email_suppressions
WHERE address_hash = @address_hash AND cleared_at IS NULL;

-- name: MessageByProviderID :one
SELECT id, tenant_id, template, status
FROM platform.email_messages
WHERE provider = @provider AND provider_message_id = @provider_message_id;

-- name: SetMessageStatus :exec
UPDATE platform.email_messages
SET status = @status, status_reason = @status_reason, updated_at = now()
WHERE id = @id;

-- name: Suppress :exec
-- A second hard bounce or complaint for an address already suppressed keeps
-- the first suppression.
INSERT INTO platform.email_suppressions (tenant_id, address_hash, address_hint, reason, detail, message_id)
VALUES (@tenant_id, @address_hash, @address_hint, @reason, @detail, @message_id)
ON CONFLICT (address_hash) WHERE cleared_at IS NULL DO NOTHING;

-- name: ListMessagesTo :many
SELECT id, template, status, status_reason, sent_at, updated_at
FROM platform.email_messages
WHERE tenant_id = @tenant_id AND to_hash = @to_hash
ORDER BY sent_at DESC
LIMIT @lim;

-- name: ListSuppressions :many
SELECT id, address_hint, reason, detail, created_at
FROM platform.email_suppressions
WHERE tenant_id = @tenant_id AND cleared_at IS NULL
ORDER BY created_at DESC
LIMIT @lim;

-- name: ClearSuppression :one
UPDATE platform.email_suppressions
SET cleared_at = now(), cleared_by = @cleared_by
WHERE id = @id AND tenant_id = @tenant_id AND cleared_at IS NULL
RETURNING address_hint, reason;

-- name: DeleteMessagesBefore :execrows
DELETE FROM platform.email_messages WHERE sent_at < @before;
