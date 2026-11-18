-- Queries for the agents domain.

-- GetAgentStatusByID finds no agent of a suspended or deleted organization.
-- name: GetAgentStatusByID :one
SELECT a.status FROM auth.agents a
JOIN organization.organizations t ON t.id = a.organization_id AND t.status = 'active' AND t.deleted_at IS NULL
WHERE a.id = $1;

-- LockAgentStatus holds one of the organization's agents while its status changes.
-- name: LockAgentStatus :one
SELECT status FROM auth.agents WHERE id = @id AND organization_id = @organization_id FOR UPDATE;

-- SponsorBelongsToOrganization reports whether the user is a member of the organization:
-- its own account, or holding a role there.
-- name: SponsorBelongsToOrganization :one
SELECT EXISTS (
    SELECT 1 FROM account.users WHERE id = @user_id AND organization_id = @organization_id::uuid AND deleted_at IS NULL
    UNION ALL
    SELECT 1 FROM rbac.user_roles WHERE organization_id = @organization_id::uuid AND user_id = @user_id
);

-- name: CreateAgent :one
INSERT INTO auth.agents (organization_id, name, secret_hash, scopes, token_ttl_seconds, sponsor_user_id)
VALUES (@organization_id, @name, @secret_hash, @scopes, @token_ttl_seconds, @sponsor_user_id)
RETURNING id, name, scopes, token_ttl_seconds, sponsor_user_id, created_at;

-- name: ListAgents :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, name, scopes, token_ttl_seconds, status, sponsor_user_id, created_at, last_used_at, previous_secret_expires_at
FROM auth.agents
WHERE organization_id = $1 AND status <> 'decommissioned'
ORDER BY created_at DESC
LIMIT 1001;

-- name: ListAgentsSponsoredBy :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, name, scopes, token_ttl_seconds, status, sponsor_user_id, created_at
FROM auth.agents
WHERE organization_id = @organization_id AND sponsor_user_id = @user_id AND status <> 'decommissioned'
ORDER BY created_at DESC
LIMIT 1001;

-- name: TransferAgentSponsor :execrows
UPDATE auth.agents SET sponsor_user_id = @to_user_id
WHERE organization_id = @organization_id AND sponsor_user_id = @from_user_id AND status <> 'decommissioned';

-- name: DeleteAgent :execrows
DELETE FROM auth.agents WHERE id = @id AND organization_id = @organization_id;

-- name: KillAllAgents :execrows
UPDATE auth.agents SET status = 'suspended'
WHERE organization_id = $1 AND status = 'active';

-- GetAgentForToken finds no agent of a suspended or deleted organization.
-- name: GetAgentForToken :one
SELECT a.organization_id, a.secret_hash, a.scopes, a.token_ttl_seconds, a.status, a.previous_secret_hash, a.previous_secret_expires_at
FROM auth.agents a
JOIN organization.organizations t ON t.id = a.organization_id AND t.status = 'active' AND t.deleted_at IS NULL
WHERE a.id = $1;

-- TouchAgent notes a token issued to the agent, at most once a minute.
-- name: TouchAgent :exec
UPDATE auth.agents SET last_used_at = NOW()
WHERE id = @id AND organization_id = @organization_id AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute');

-- RotateAgentSecret makes the new secret current and keeps the old one
-- working until previous_expires_at.
-- name: RotateAgentSecret :one
UPDATE auth.agents
SET previous_secret_hash = secret_hash, previous_secret_expires_at = @previous_expires_at, secret_hash = @secret_hash
WHERE id = @id AND organization_id = @organization_id AND status <> 'decommissioned'
RETURNING name;

-- name: ResumeAllAgents :execrows
UPDATE auth.agents SET status = 'active'
WHERE organization_id = $1 AND status = 'suspended';

-- name: SetAgentStatus :exec
UPDATE auth.agents SET status = @status
WHERE id = @id AND organization_id = @organization_id;

-- AgentScopes returns the scopes of one of the organization's agents still in service.
-- name: AgentScopes :one
SELECT scopes FROM auth.agents WHERE id = @id AND organization_id = @organization_id AND status <> 'decommissioned';
