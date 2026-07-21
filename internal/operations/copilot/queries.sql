-- Queries for the copilot domain.
-- Static queries against copilot.conversations and copilot.messages; compiled
-- by sqlc into ./dbgen. All queries are scoped by tenant_id (multi-tenancy).

-- name: CreateConversation :one
INSERT INTO copilot.conversations (tenant_id, user_id, title)
VALUES (@tenant_id, @user_id, @title)
RETURNING id, tenant_id, user_id, title, pinned, created_at, updated_at;

-- name: ListConversations :many
SELECT id, tenant_id, user_id, title, pinned, created_at, updated_at
FROM copilot.conversations
WHERE tenant_id = @tenant_id AND user_id = @user_id
ORDER BY pinned DESC, updated_at DESC;

-- name: GetConversation :one
SELECT id, tenant_id, user_id, title, pinned, created_at, updated_at
FROM copilot.conversations
WHERE id = @id AND tenant_id = @tenant_id AND user_id = @user_id;

-- name: PatchConversation :one
UPDATE copilot.conversations
SET
    title      = COALESCE(sqlc.narg('title'), title),
    pinned     = COALESCE(sqlc.narg('pinned'), pinned),
    updated_at = now()
WHERE id = @id AND tenant_id = @tenant_id AND user_id = @user_id
RETURNING id, tenant_id, user_id, title, pinned, created_at, updated_at;

-- name: DeleteConversation :execrows
DELETE FROM copilot.conversations
WHERE id = @id AND tenant_id = @tenant_id AND user_id = @user_id;

-- name: InsertMessage :one
INSERT INTO copilot.messages (tenant_id, conversation_id, role, content)
VALUES (@tenant_id, @conversation_id, @role, @content)
RETURNING id, tenant_id, conversation_id, role, content, created_at;

-- name: TouchConversation :exec
UPDATE copilot.conversations
SET updated_at = now()
WHERE id = @conversation_id AND tenant_id = @tenant_id;

-- name: ListMessages :many
SELECT id, tenant_id, conversation_id, role, content, created_at
FROM copilot.messages
WHERE conversation_id = @conversation_id AND tenant_id = @tenant_id
ORDER BY created_at ASC;
