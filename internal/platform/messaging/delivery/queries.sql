-- Queries for email delivery records and the suppression list.

-- name: InsertMessage :one
INSERT INTO platform.email_messages
    (organization_id, to_hash, to_hint, template, provider, provider_message_id, status, status_reason)
VALUES (@organization_id, @to_hash, @to_hint, @template, @provider, sqlc.narg(provider_message_id), @status, @status_reason)
RETURNING id;

-- name: ActiveSuppression :one
SELECT id, organization_id, reason, detail, created_at
FROM platform.email_suppressions
WHERE address_hash = @address_hash AND cleared_at IS NULL;

-- name: MessageByProviderID :one
SELECT id, organization_id, template, status
FROM platform.email_messages
WHERE provider = @provider AND provider_message_id = @provider_message_id;

-- name: SetMessageStatus :exec
UPDATE platform.email_messages
SET status = @status, status_reason = @status_reason, updated_at = now()
WHERE id = @id;

-- name: Suppress :exec
-- A second hard bounce or complaint for an address already suppressed keeps
-- the first suppression.
INSERT INTO platform.email_suppressions (organization_id, address_hash, address_hint, reason, detail, message_id)
VALUES (@organization_id, @address_hash, @address_hint, @reason, @detail, @message_id)
ON CONFLICT (address_hash) WHERE cleared_at IS NULL DO NOTHING;

-- name: ListMessagesTo :many
SELECT id, template, status, status_reason, sent_at, updated_at
FROM platform.email_messages
WHERE organization_id = @organization_id AND to_hash = @to_hash
  AND (sqlc.narg('before_ts')::timestamptz IS NULL OR sent_at < sqlc.narg('before_ts')
       OR (sent_at = sqlc.narg('before_ts') AND id < sqlc.narg('before_id')::uuid))
ORDER BY sent_at DESC, id DESC
LIMIT @lim;

-- name: ListSuppressions :many
SELECT id, address_hint, reason, detail, created_at
FROM platform.email_suppressions
WHERE organization_id = @organization_id AND cleared_at IS NULL
  AND (sqlc.narg('before_ts')::timestamptz IS NULL OR created_at < sqlc.narg('before_ts')
       OR (created_at = sqlc.narg('before_ts') AND id < sqlc.narg('before_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT @lim;

-- name: ClearSuppression :one
UPDATE platform.email_suppressions
SET cleared_at = now(), cleared_by = @cleared_by
WHERE id = @id AND organization_id = @organization_id AND cleared_at IS NULL
RETURNING address_hint, reason;

-- DeleteMessagesBefore deletes at most @max_rows message records sent before
-- @before.
-- name: DeleteMessagesBefore :execrows
DELETE FROM platform.email_messages WHERE ctid = ANY(ARRAY(
    SELECT m.ctid FROM platform.email_messages m WHERE m.sent_at < @before LIMIT @max_rows));
