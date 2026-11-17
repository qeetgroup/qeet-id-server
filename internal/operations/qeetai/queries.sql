-- Queries for the qeetai domain.
-- Static queries against qeetai.conversations and qeetai.messages; compiled
-- by sqlc into ./dbgen. All queries are scoped by organization_id (multi-tenancy).

-- name: CreateConversation :one
INSERT INTO qeetai.conversations (organization_id, user_id, title)
VALUES (@organization_id, @user_id, @title)
RETURNING id, organization_id, user_id, title, pinned, created_at, updated_at;

-- name: ListConversations :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, user_id, title, pinned, created_at, updated_at
FROM qeetai.conversations
WHERE organization_id = @organization_id AND user_id = @user_id
ORDER BY pinned DESC, updated_at DESC
LIMIT 1001;

-- name: GetConversation :one
SELECT id, organization_id, user_id, title, pinned, created_at, updated_at
FROM qeetai.conversations
WHERE id = @id AND organization_id = @organization_id AND user_id = @user_id;

-- name: PatchConversation :one
UPDATE qeetai.conversations
SET
    title      = COALESCE(sqlc.narg('title'), title),
    pinned     = COALESCE(sqlc.narg('pinned'), pinned),
    updated_at = now()
WHERE id = @id AND organization_id = @organization_id AND user_id = @user_id
RETURNING id, organization_id, user_id, title, pinned, created_at, updated_at;

-- name: DeleteConversation :execrows
DELETE FROM qeetai.conversations
WHERE id = @id AND organization_id = @organization_id AND user_id = @user_id;

-- name: InsertMessage :one
INSERT INTO qeetai.messages (organization_id, conversation_id, role, content)
VALUES (@organization_id, @conversation_id, @role, @content)
RETURNING id, organization_id, conversation_id, role, content, created_at;

-- name: TouchConversation :exec
UPDATE qeetai.conversations
SET updated_at = now()
WHERE id = @conversation_id AND organization_id = @organization_id;

-- name: ListMessages :many
SELECT id, organization_id, conversation_id, role, content, created_at
FROM qeetai.messages
WHERE conversation_id = @conversation_id AND organization_id = @organization_id
ORDER BY created_at ASC;

-- name: ListRecentMessages :many
-- The conversation's latest @max_messages messages, newest first: the most of
-- its history one turn sends the model.
SELECT id, organization_id, conversation_id, role, content, created_at
FROM qeetai.messages
WHERE conversation_id = @conversation_id AND organization_id = @organization_id
ORDER BY created_at DESC
LIMIT @max_messages;

-- name: ClaimConversationTurn :one
-- Start a turn of the conversation, unless another started less than
-- @stale_after_seconds ago and so may still be running; no row then. Returns
-- when this turn started, which releasing it names.
INSERT INTO qeetai.conversation_turns (conversation_id, organization_id)
VALUES (@conversation_id, @organization_id)
ON CONFLICT (conversation_id) DO UPDATE SET started_at = now()
WHERE qeetai.conversation_turns.organization_id = @organization_id
  AND qeetai.conversation_turns.started_at < now() - make_interval(secs => @stale_after_seconds::float8)
RETURNING started_at;

-- name: ReleaseConversationTurn :exec
-- End the turn that started at @started_at, unless a later one has taken over.
DELETE FROM qeetai.conversation_turns
WHERE conversation_id = @conversation_id AND organization_id = @organization_id AND started_at = @started_at;

-- Per-organization BYOK provider settings. The key is stored encrypted (ciphertext +
-- nonce); it is never selected into any response DTO — only the service layer
-- decrypts it to build the provider client.

-- name: GetProviderSettings :one
SELECT organization_id, provider, model, base_url, max_tokens,
       key_ciphertext, key_nonce, key_last4, enabled, updated_by, created_at, updated_at
FROM qeetai.provider_settings
WHERE organization_id = @organization_id;

-- name: UpsertProviderSettings :one
INSERT INTO qeetai.provider_settings (
    organization_id, provider, model, base_url, max_tokens,
    key_ciphertext, key_nonce, key_last4, enabled, updated_by, updated_at
) VALUES (
    @organization_id, @provider, @model, @base_url, @max_tokens,
    @key_ciphertext, @key_nonce, @key_last4, @enabled, sqlc.narg('updated_by'), now()
)
ON CONFLICT (organization_id) DO UPDATE SET
    provider       = EXCLUDED.provider,
    model          = EXCLUDED.model,
    base_url       = EXCLUDED.base_url,
    max_tokens     = EXCLUDED.max_tokens,
    key_ciphertext = EXCLUDED.key_ciphertext,
    key_nonce      = EXCLUDED.key_nonce,
    key_last4      = EXCLUDED.key_last4,
    enabled        = EXCLUDED.enabled,
    updated_by     = EXCLUDED.updated_by,
    updated_at     = now()
RETURNING organization_id, provider, model, base_url, max_tokens,
          key_ciphertext, key_nonce, key_last4, enabled, updated_by, created_at, updated_at;

-- name: DeleteProviderSettings :execrows
DELETE FROM qeetai.provider_settings
WHERE organization_id = @organization_id;

-- name: RecordUsage :exec
-- Adds one turn and its tokens to the organization's month.
INSERT INTO qeetai.usage (organization_id, month, messages, input_tokens, output_tokens, last_used_at)
VALUES (@organization_id, date_trunc('month', NOW() AT TIME ZONE 'UTC')::date, 1, @input_tokens, @output_tokens, NOW())
ON CONFLICT (organization_id, month) DO UPDATE SET
    messages      = qeetai.usage.messages + 1,
    input_tokens  = qeetai.usage.input_tokens + EXCLUDED.input_tokens,
    output_tokens = qeetai.usage.output_tokens + EXCLUDED.output_tokens,
    last_used_at  = NOW();

-- name: ListUsage :many
-- The organization's last twelve months of use, newest first.
SELECT month, messages, input_tokens, output_tokens, last_used_at
FROM qeetai.usage WHERE organization_id = @organization_id
ORDER BY month DESC LIMIT 12;

-- name: GetSettings :one
SELECT s.conversation_retention_days, s.updated_by, u.email AS updated_by_email, s.updated_at
FROM qeetai.settings s
LEFT JOIN account.users u ON u.id = s.updated_by
WHERE s.organization_id = @organization_id;

-- name: UpsertSettings :exec
INSERT INTO qeetai.settings (organization_id, conversation_retention_days, updated_by, updated_at)
VALUES (@organization_id, sqlc.narg('conversation_retention_days'), sqlc.narg('updated_by'), NOW())
ON CONFLICT (organization_id) DO UPDATE SET
    conversation_retention_days = EXCLUDED.conversation_retention_days,
    updated_by = EXCLUDED.updated_by, updated_at = NOW();

-- name: ListConversationRetention :many
-- Every organization that keeps its conversations for a set time.
SELECT organization_id, conversation_retention_days::int AS days
FROM qeetai.settings WHERE conversation_retention_days IS NOT NULL;

-- name: DeleteExpiredConversations :execrows
-- Deletes, with their messages, up to row_limit of the organization's
-- conversations untouched for days.
DELETE FROM qeetai.conversations WHERE id IN (
    SELECT c.id FROM qeetai.conversations c
    WHERE c.organization_id = @organization_id AND c.updated_at < NOW() - make_interval(days => @days::int)
    LIMIT @row_limit);
