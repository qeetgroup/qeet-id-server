-- Queries for the agents domain.
-- Dynamic SQL in transition() (disabled_at = NOW() vs NULL for suspend/resume)
-- is handled as two separate static queries below.

-- name: GetAgentStatusByID :one
SELECT status FROM auth.agents WHERE id = $1;

-- name: GetAgentStatus :one
SELECT status FROM auth.agents WHERE id = @id AND tenant_id = @tenant_id;

-- name: SponsorBelongsToTenant :one
SELECT EXISTS (
    SELECT 1 FROM rbac.user_roles WHERE user_id = @user_id AND tenant_id = @tenant_id
);

-- name: CreateAgent :one
INSERT INTO auth.agents (tenant_id, name, secret_hash, scopes, token_ttl_seconds, sponsor_user_id)
VALUES (@tenant_id, @name, @secret_hash, @scopes, @token_ttl_seconds, @sponsor_user_id)
RETURNING id, name, scopes, token_ttl_seconds, sponsor_user_id, created_at;

-- name: ListAgents :many
SELECT id, name, scopes, token_ttl_seconds, status, sponsor_user_id, created_at
FROM auth.agents
WHERE tenant_id = $1 AND status <> 'decommissioned'
ORDER BY created_at DESC;

-- name: ListAgentsSponsoredBy :many
SELECT id, name, scopes, token_ttl_seconds, status, sponsor_user_id, created_at
FROM auth.agents
WHERE tenant_id = @tenant_id AND sponsor_user_id = @user_id AND status <> 'decommissioned'
ORDER BY created_at DESC;

-- name: TransferAgentSponsor :execrows
UPDATE auth.agents SET sponsor_user_id = @to_user_id
WHERE tenant_id = @tenant_id AND sponsor_user_id = @from_user_id AND status <> 'decommissioned';

-- name: DeleteAgent :execrows
DELETE FROM auth.agents WHERE id = @id AND tenant_id = @tenant_id;

-- name: KillAllAgents :execrows
UPDATE auth.agents SET status = 'suspended', disabled_at = NOW()
WHERE tenant_id = $1 AND status = 'active';

-- name: GetAgentForToken :one
SELECT tenant_id, secret_hash, scopes, token_ttl_seconds, status
FROM auth.agents WHERE id = $1;

-- Transition helpers: resume sets status active and clears disabled_at;
-- suspend/decommission sets the given status and stamps disabled_at = NOW().

-- name: ResumeAgent :exec
UPDATE auth.agents SET status = 'active', disabled_at = NULL
WHERE id = @id AND tenant_id = @tenant_id;

-- name: DeactivateAgent :exec
UPDATE auth.agents SET status = @status, disabled_at = NOW()
WHERE id = @id AND tenant_id = @tenant_id;
