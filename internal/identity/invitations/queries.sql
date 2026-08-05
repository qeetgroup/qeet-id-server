-- Queries for the invitations domain.
-- Static queries against tenant.invites live here and are compiled by sqlc into ./dbgen.
-- The cross-context writes inside Accept (user.users, auth.password_credentials,
-- rbac.user_roles) also go through sqlc — run on the same pgx.Tx via q.WithTx(tx).

-- name: InsertInvite :one
INSERT INTO tenant.invites (tenant_id, email, role_id, invited_by, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, tenant_id, email, role_id, status, expires_at, accepted_at, created_at;

-- CountSeats returns the tenant's seats in use = distinct members (users holding
-- any role in the tenant) plus still-actionable pending invites. Backs the plan
-- seat limit checked before an invite/user is created.
-- name: CountSeats :one
SELECT (
    (SELECT COUNT(DISTINCT user_id) FROM rbac.user_roles WHERE tenant_id = @tenant_id::uuid)
    + (SELECT COUNT(*) FROM tenant.invites
        WHERE tenant_id = @tenant_id::uuid AND status = 'pending' AND expires_at > NOW())
)::bigint AS seats;

-- name: ListInvites :many
SELECT id, tenant_id, email, role_id, status, expires_at, accepted_at, created_at
FROM tenant.invites
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 200;

-- name: RevokeInvite :execrows
UPDATE tenant.invites SET status = 'revoked'
WHERE id = $1 AND tenant_id = $2 AND status = 'pending';

-- RegenerateInvite rotates the token + extends the expiry for a resend (a fresh
-- link; the old one stops working). Also revives an expired invite back to
-- pending. Accepted/revoked invites are left untouched (0 rows).
-- name: RegenerateInvite :one
UPDATE tenant.invites
SET token_hash = $3, expires_at = $4, status = 'pending'
WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'expired')
RETURNING id, tenant_id, email, role_id, status, expires_at, accepted_at, created_at;

-- GetInviteForAccept locks the row for update so concurrent Accept calls
-- don't race on the same token.
-- name: GetInviteForAccept :one
SELECT id, tenant_id, email, role_id, status, expires_at
FROM tenant.invites
WHERE token_hash = $1
FOR UPDATE;

-- GetInviteByIDForAccept is the by-id counterpart used by the in-app "accept
-- from my inbox" flow (the caller never sees the raw token).
-- name: GetInviteByIDForAccept :one
SELECT id, tenant_id, email, role_id, status, expires_at
FROM tenant.invites
WHERE id = $1
FOR UPDATE;

-- ListInvitesForEmail returns the pending, unexpired invites addressed to a
-- signed-in user's email, with the inviting org's display name — the "pending
-- invitations" inbox for a user who may not belong to any org yet.
-- DeclineInviteForEmail lets an invitee dismiss a pending invite addressed to
-- their own email (scoped by email so one user can't decline another's).
-- name: DeclineInviteForEmail :execrows
UPDATE tenant.invites SET status = 'declined'
WHERE id = @id AND email = @email AND status = 'pending';

-- name: ListInvitesForEmail :many
SELECT i.id, i.tenant_id, i.email, i.role_id, i.expires_at, i.created_at,
       t.name AS tenant_name, t.slug AS tenant_slug
FROM tenant.invites i
JOIN tenant.tenants t ON t.id = i.tenant_id
WHERE i.email = @email AND i.status = 'pending' AND i.expires_at > NOW()
ORDER BY i.created_at DESC
LIMIT 50;

-- name: MarkInviteExpired :exec
UPDATE tenant.invites SET status = 'expired' WHERE id = $1;

-- name: MarkInviteAccepted :exec
UPDATE tenant.invites SET status = 'accepted', accepted_at = NOW() WHERE id = $1;

-- FindUserIDByEmail resolves an existing account by its (globally-unique) email;
-- pgx.ErrNoRows means no account exists yet. Used by Accept to branch between
-- creating a new user and attaching a membership to an existing one.
-- name: FindUserIDByEmail :one
SELECT id FROM "user".users WHERE email = @email;

-- GetUserEmailByID returns the caller's email so an authenticated accept can
-- confirm the invite was addressed to them.
-- name: GetUserEmailByID :one
SELECT email FROM "user".users WHERE id = @user_id;

-- InsertInvitedUser creates a brand-new invited account (no prior user). The
-- invited email is pre-verified (they proved control by receiving the link).
-- name: InsertInvitedUser :one
INSERT INTO "user".users (tenant_id, email, display_name, status, email_verified_at)
VALUES (@tenant_id, @email, NULLIF(@display_name, ''), 'active', NOW())
RETURNING id;

-- name: InsertInviteCredential :exec
INSERT INTO auth.password_credentials (user_id, password_hash) VALUES (@user_id, @password_hash);

-- GrantUserRole attaches a tenant membership idempotently: re-accepting or a
-- duplicate role grant is a no-op rather than a PK violation.
-- name: GrantUserRole :exec
INSERT INTO rbac.user_roles (user_id, tenant_id, role_id)
VALUES (@user_id, @tenant_id, @role_id)
ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING;
