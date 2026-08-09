-- Queries for the qeetai domain.
-- Static queries against qeetai.conversations and qeetai.messages; compiled
-- by sqlc into ./dbgen. All queries are scoped by tenant_id (multi-tenancy).

-- name: CreateConversation :one
INSERT INTO qeetai.conversations (tenant_id, user_id, title)
VALUES (@tenant_id, @user_id, @title)
RETURNING id, tenant_id, user_id, title, pinned, created_at, updated_at;

-- name: ListConversations :many
SELECT id, tenant_id, user_id, title, pinned, created_at, updated_at
FROM qeetai.conversations
WHERE tenant_id = @tenant_id AND user_id = @user_id
ORDER BY pinned DESC, updated_at DESC;

-- name: GetConversation :one
SELECT id, tenant_id, user_id, title, pinned, created_at, updated_at
FROM qeetai.conversations
WHERE id = @id AND tenant_id = @tenant_id AND user_id = @user_id;

-- name: PatchConversation :one
UPDATE qeetai.conversations
SET
    title      = COALESCE(sqlc.narg('title'), title),
    pinned     = COALESCE(sqlc.narg('pinned'), pinned),
    updated_at = now()
WHERE id = @id AND tenant_id = @tenant_id AND user_id = @user_id
RETURNING id, tenant_id, user_id, title, pinned, created_at, updated_at;

-- name: DeleteConversation :execrows
DELETE FROM qeetai.conversations
WHERE id = @id AND tenant_id = @tenant_id AND user_id = @user_id;

-- name: InsertMessage :one
INSERT INTO qeetai.messages (tenant_id, conversation_id, role, content)
VALUES (@tenant_id, @conversation_id, @role, @content)
RETURNING id, tenant_id, conversation_id, role, content, created_at;

-- name: TouchConversation :exec
UPDATE qeetai.conversations
SET updated_at = now()
WHERE id = @conversation_id AND tenant_id = @tenant_id;

-- name: ListMessages :many
SELECT id, tenant_id, conversation_id, role, content, created_at
FROM qeetai.messages
WHERE conversation_id = @conversation_id AND tenant_id = @tenant_id
ORDER BY created_at ASC;

-- Per-tenant BYOK provider settings. The key is stored encrypted (ciphertext +
-- nonce); it is never selected into any response DTO — only the service layer
-- decrypts it to build the provider client.

-- name: GetProviderSettings :one
SELECT tenant_id, provider, model, base_url, max_tokens,
       key_ciphertext, key_nonce, key_last4, enabled, updated_by, created_at, updated_at
FROM qeetai.provider_settings
WHERE tenant_id = @tenant_id;

-- name: UpsertProviderSettings :one
INSERT INTO qeetai.provider_settings (
    tenant_id, provider, model, base_url, max_tokens,
    key_ciphertext, key_nonce, key_last4, enabled, updated_by, updated_at
) VALUES (
    @tenant_id, @provider, @model, @base_url, @max_tokens,
    @key_ciphertext, @key_nonce, @key_last4, @enabled, sqlc.narg('updated_by'), now()
)
ON CONFLICT (tenant_id) DO UPDATE SET
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
RETURNING tenant_id, provider, model, base_url, max_tokens,
          key_ciphertext, key_nonce, key_last4, enabled, updated_by, created_at, updated_at;

-- name: DeleteProviderSettings :execrows
DELETE FROM qeetai.provider_settings
WHERE tenant_id = @tenant_id;
