-- Queries for the invitations domain.
-- Static queries against tenant.invites live here and are compiled by sqlc into ./dbgen.
-- Cross-context writes inside Accept (user.users, auth.password_credentials,
-- rbac.user_roles) intentionally remain hand-written on the same pgx.Tx.

-- name: InsertInvite :one
INSERT INTO tenant.invites (tenant_id, email, role_id, invited_by, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, tenant_id, email, role_id, status, expires_at, accepted_at, created_at;

-- name: ListInvites :many
SELECT id, tenant_id, email, role_id, status, expires_at, accepted_at, created_at
FROM tenant.invites
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 200;

-- name: RevokeInvite :execrows
UPDATE tenant.invites SET status = 'revoked'
WHERE id = $1 AND status = 'pending';

-- GetInviteForAccept locks the row for update so concurrent Accept calls
-- don't race on the same token.
-- name: GetInviteForAccept :one
SELECT id, tenant_id, email, role_id, status, expires_at
FROM tenant.invites
WHERE token_hash = $1
FOR UPDATE;

-- name: MarkInviteExpired :exec
UPDATE tenant.invites SET status = 'expired' WHERE id = $1;

-- name: MarkInviteAccepted :exec
UPDATE tenant.invites SET status = 'accepted', accepted_at = NOW() WHERE id = $1;
