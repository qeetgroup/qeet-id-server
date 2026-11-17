-- Queries for the invitations domain.
-- Static queries against organization.invites live here and are compiled by sqlc into ./dbgen.
-- The cross-context writes inside Accept (account.users, auth.password_credentials,
-- rbac.user_roles) also go through sqlc — run on the same pgx.Tx via q.WithTx(tx).

-- InsertInvite creates an invitation. One that carries a role is created only
-- when the role is the organization's: pgx.ErrNoRows otherwise, for a missing and a
-- foreign role alike.
-- name: InsertInvite :one
INSERT INTO organization.invites (organization_id, email, role_id, invited_by, token_hash, expires_at)
SELECT @organization_id, @email, @role_id, @invited_by, @token_hash, @expires_at
WHERE @role_id::uuid IS NULL
   OR EXISTS (SELECT 1 FROM rbac.roles ro WHERE ro.id = @role_id AND ro.organization_id = @organization_id)
RETURNING id, organization_id, email, role_id, status, expires_at, accepted_at, created_at;

-- CountSeats returns the organization's seats in use = distinct members (users holding
-- any role in the organization, directly or through a group that carries one) plus
-- still-actionable pending invites. Backs the plan seat limit and the usage
-- display; CountSeatHolders and CountPendingInvites are its two halves.
-- name: CountSeats :one
SELECT (
    (SELECT COUNT(*) FROM (
        SELECT ur.user_id FROM rbac.user_roles ur WHERE ur.organization_id = @organization_id::uuid
        UNION
        SELECT gm.user_id FROM organization.group_members gm
        JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
        WHERE gm.organization_id = @organization_id::uuid
    ) holders)
    + (SELECT COUNT(*) FROM organization.invites
        WHERE organization_id = @organization_id::uuid AND status = 'pending' AND expires_at > NOW())
)::bigint AS seats;

-- CountSeatHolders counts the people holding a role in the organization, directly or
-- through a group that carries one: one seat each, however many roles.
-- name: CountSeatHolders :one
SELECT COUNT(*)::bigint AS holders FROM (
    SELECT ur.user_id FROM rbac.user_roles ur WHERE ur.organization_id = @organization_id::uuid
    UNION
    SELECT gm.user_id FROM organization.group_members gm
    JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
    WHERE gm.organization_id = @organization_id::uuid
) holders;

-- name: CountPendingInvites :one
SELECT COUNT(*)::bigint AS pending FROM organization.invites
WHERE organization_id = @organization_id::uuid AND status = 'pending' AND expires_at > NOW();

-- LockSeats holds the organization's seats until the transaction ends, so two
-- changes can't each take the last one.
-- name: LockSeats :exec
SELECT pg_advisory_xact_lock(hashtext('seats'), hashtext(sqlc.arg(organization_id)::uuid::text));

-- name: ListInvites :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, email, role_id, status, expires_at, accepted_at, created_at
FROM organization.invites
WHERE organization_id = $1
ORDER BY created_at DESC
LIMIT 1001;

-- name: RevokeInvite :one
UPDATE organization.invites SET status = 'revoked'
WHERE id = $1 AND organization_id = $2 AND status = 'pending'
RETURNING email, role_id;

-- name: GetInviteRole :one
SELECT role_id FROM organization.invites WHERE id = $1 AND organization_id = $2;

-- RegenerateInvite rotates the token + extends the expiry for a resend (a fresh
-- link; the old one stops working). Also revives an expired invite back to
-- pending. Accepted/revoked invites are left untouched (0 rows).
-- name: RegenerateInvite :one
UPDATE organization.invites
SET token_hash = $3, expires_at = $4, status = 'pending'
WHERE id = $1 AND organization_id = $2 AND status IN ('pending', 'expired')
RETURNING id, organization_id, email, role_id, status, expires_at, accepted_at, created_at;

-- GetInviteForAccept locks the row for update so concurrent Accept calls
-- don't race on the same token.
-- name: GetInviteForAccept :one
SELECT id, organization_id, email, role_id, status, expires_at
FROM organization.invites
WHERE token_hash = $1
FOR UPDATE;

-- InviteSenderByToken is who sent the invitation a token names, and what it
-- gives, for the check acceptance makes before its transaction.
-- name: InviteSenderByToken :one
SELECT organization_id, role_id, invited_by, status, expires_at FROM organization.invites WHERE token_hash = $1;

-- InviteSenderByID is InviteSenderByToken for an invitation picked by id.
-- name: InviteSenderByID :one
SELECT organization_id, role_id, invited_by, status, expires_at FROM organization.invites WHERE id = $1;

-- InviterActive reports whether the account that sent an invitation is active
-- and still belongs to its organization: at home there or holding a role.
-- name: InviterActive :one
SELECT EXISTS (
    SELECT 1 FROM account.users u
    WHERE u.id = @user_id AND u.status = 'active' AND u.deleted_at IS NULL
      AND (u.organization_id = @organization_id::uuid OR EXISTS (
          SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.organization_id = @organization_id::uuid))
);

-- GetInviteByIDForAccept is the by-id counterpart used by the in-app "accept
-- from my inbox" flow (the caller never sees the raw token).
-- name: GetInviteByIDForAccept :one
SELECT id, organization_id, email, role_id, status, expires_at
FROM organization.invites
WHERE id = $1
FOR UPDATE;

-- ListInvitesForEmail returns the pending, unexpired invites addressed to a
-- signed-in user's email, with the inviting org's display name — the "pending
-- invitations" inbox for a user who may not belong to any org yet.
-- DeclineInviteForEmail lets an invitee dismiss a pending invite addressed to
-- their own email (scoped by email so one user can't decline another's).
-- name: DeclineInviteForEmail :one
UPDATE organization.invites SET status = 'declined'
WHERE id = @id AND LOWER(email) = LOWER(@email) AND status = 'pending'
RETURNING organization_id, role_id;

-- name: ListInvitesForEmail :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT i.id, i.organization_id, i.email, i.role_id, i.expires_at, i.created_at,
       t.name AS organization_name, t.slug AS organization_slug
FROM organization.invites i
JOIN organization.organizations t ON t.id = i.organization_id
WHERE LOWER(i.email) = LOWER(@email) AND i.status = 'pending' AND i.expires_at > NOW()
ORDER BY i.created_at DESC
LIMIT 1001;

-- name: MarkInviteExpired :exec
UPDATE organization.invites SET status = 'expired' WHERE id = $1;

-- name: MarkInviteAccepted :exec
UPDATE organization.invites SET status = 'accepted', accepted_at = NOW() WHERE id = $1;

-- FindUserIDByEmail resolves an existing account by its (globally-unique) email;
-- pgx.ErrNoRows means no account exists yet. Used by Accept to branch between
-- creating a new user and attaching a membership to an existing one.
-- name: FindUserIDByEmail :one
SELECT id FROM account.users WHERE LOWER(email) = LOWER(@email);

-- AccountHomeElsewhere reports whether an account holds @email and has a home
-- other than @organization_id, so an invitation with no role would join it to
-- nothing.
-- name: AccountHomeElsewhere :one
SELECT EXISTS (
    SELECT 1 FROM account.users u
    WHERE LOWER(u.email) = LOWER(@email) AND u.deleted_at IS NULL
      AND u.organization_id IS DISTINCT FROM @organization_id::uuid
)::bool;

-- GetUserEmailByID returns the caller's email so an authenticated accept can
-- confirm the invite was addressed to them.
-- name: GetUserEmailByID :one
SELECT email FROM account.users WHERE id = @user_id;

-- GetInboxEmail is the address the in-app invitations inbox is keyed on, and
-- whether the account has proven it. Anyone can sign up with any address, so an
-- unproven one opens nothing.
-- name: GetInboxEmail :one
SELECT email, (email_verified_at IS NOT NULL)::boolean AS verified
FROM account.users WHERE id = @user_id AND deleted_at IS NULL;

-- InsertInvitedUser creates a brand-new invited account (no prior user). Its
-- address is left unverified; a code or link sent to it later verifies it.
-- name: InsertInvitedUser :one
INSERT INTO account.users (organization_id, email, display_name, status)
VALUES (@organization_id, @email, NULLIF(@display_name, ''), 'active')
RETURNING id;

-- name: InsertInviteCredential :exec
INSERT INTO auth.password_credentials (user_id, password_hash) VALUES (@user_id, @password_hash);

-- GrantUserRole attaches an organization membership idempotently: re-accepting or a
-- duplicate role grant is a no-op rather than a PK violation. It writes only a
-- role of @organization_id.
-- name: GrantUserRole :exec
INSERT INTO rbac.user_roles (user_id, organization_id, role_id)
SELECT @user_id, @organization_id, @role_id
WHERE EXISTS (SELECT 1 FROM rbac.roles ro WHERE ro.id = @role_id AND ro.organization_id = @organization_id)
ON CONFLICT (user_id, organization_id, role_id) DO NOTHING;

-- LookupInvite reads the invitation a link names for the acceptance screen:
-- the organization it is from, the address it is for, its state, and whether
-- an account already holds that address. Read-only.
-- name: LookupInvite :one
SELECT i.id, i.organization_id, i.email, i.status, i.expires_at,
       t.name AS organization_name, t.slug AS organization_slug,
       EXISTS (SELECT 1 FROM account.users u WHERE LOWER(u.email) = LOWER(i.email)) AS account_exists
FROM organization.invites i
JOIN organization.organizations t ON t.id = i.organization_id
WHERE i.token_hash = @token_hash;

-- ActivateInvitedAccount activates the account created to accept an
-- invitation. Its address stays unverified, as the password path's
-- InsertInvitedUser leaves it.
-- name: ActivateInvitedAccount :exec
UPDATE account.users SET status = 'active'
WHERE id = @user_id;
