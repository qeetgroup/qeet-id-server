-- Queries for the organization domain.
-- Static queries against organization.organizations live here and are compiled by sqlc into ./dbgen.
-- Dynamic queries (partial UPDATE) intentionally remain hand-written in repository.go.

-- name: GetOrganization :one
SELECT * FROM organization.organizations
WHERE id = $1 AND deleted_at IS NULL;

-- ListEligibleOrganizations lists the active organizations an active account
-- belongs to, by id: its own, and each one it holds a role in. last_used_at is
-- its newest other session there, else its last sign-in there in the audit
-- log, which outlasts the sessions the cleanup deletes.
-- name: ListEligibleOrganizations :many
SELECT t.id, t.slug, t.name, t.plan, t.region, t.logo_url,
  ARRAY(SELECT DISTINCT role.name FROM rbac.user_roles membership
    JOIN rbac.roles role ON role.id = membership.role_id AND role.organization_id = membership.organization_id
    WHERE membership.user_id = @user_id AND membership.organization_id = t.id
    ORDER BY role.name)::text[] AS roles,
  COALESCE((SELECT domain.domain FROM organization.domains domain
    WHERE domain.organization_id = t.id AND domain.verified_at IS NOT NULL
    ORDER BY domain.created_at, domain.id LIMIT 1), '')::text AS domain,
  COALESCE(GREATEST(
    (SELECT MAX(session.last_seen_at) FROM auth.sessions session
      WHERE session.user_id = @user_id AND session.organization_id = t.id
        AND session.id <> @current_session_id),
    (SELECT MAX(sign_in.created_at) FROM audit.events sign_in
      WHERE sign_in.actor_user_id = @user_id AND sign_in.organization_id = t.id
        AND sign_in.action = 'auth.login_succeeded'
        AND sign_in.resource_id IS DISTINCT FROM @current_session_id)),
    '0001-01-01 00:00:00+00'::timestamptz)::timestamptz AS last_used_at
FROM organization.organizations t
WHERE t.status = 'active' AND t.deleted_at IS NULL
  AND EXISTS (SELECT 1 FROM account.users account
    WHERE account.id = @user_id AND account.status = 'active' AND account.deleted_at IS NULL)
  AND t.id IN (SELECT account.organization_id FROM account.users account WHERE account.id = @user_id
    UNION SELECT membership.organization_id FROM rbac.user_roles membership WHERE membership.user_id = @user_id)
  AND (@after_id::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR t.id > @after_id::uuid)
ORDER BY t.id
LIMIT @row_limit;

-- IsEmailVerified reports whether the given user has a verified email — the
-- gate for self-serve org creation.
-- name: IsEmailVerified :one
SELECT (email_verified_at IS NOT NULL)::boolean FROM account.users WHERE id = @user_id;

-- name: GetOrganizationBySlug :one
SELECT * FROM organization.organizations
WHERE LOWER(slug) = LOWER(@slug) AND deleted_at IS NULL;

-- name: InsertOrganization :one
INSERT INTO organization.organizations (slug, name, plan, region, logo_url, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- ScheduleOrganizationDeletion schedules an organization's deletion for @due_at,
-- unless one is already scheduled. No row: it is deleted or already
-- scheduled.
-- name: ScheduleOrganizationDeletion :one
UPDATE organization.organizations SET deletion_due_at = @due_at::timestamptz, updated_at = NOW()
WHERE id = @id AND deleted_at IS NULL AND deletion_due_at IS NULL
RETURNING deletion_due_at;

-- CancelOrganizationDeletion calls off an organization's scheduled deletion. 0
-- rows: none was scheduled.
-- name: CancelOrganizationDeletion :execrows
UPDATE organization.organizations SET deletion_due_at = NULL, updated_at = NOW()
WHERE id = @id AND deleted_at IS NULL AND deletion_due_at IS NOT NULL;

-- ListOrganizationsDueForDeletion lists organizations whose scheduled deletion is
-- due, oldest first.
-- name: ListOrganizationsDueForDeletion :many
SELECT id FROM organization.organizations
WHERE deleted_at IS NULL AND deletion_due_at IS NOT NULL AND deletion_due_at <= NOW()
ORDER BY deletion_due_at
LIMIT @max_rows;

-- name: SoftDeleteOrganization :execrows
UPDATE organization.organizations
SET deleted_at = NOW(), status = 'deleted', updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL;

-- List the organizations a user is a member of, newest first. Cursor pagination is split
-- into a first-page and after-cursor variant (the idiomatic sqlc way to do dynamic paging).

-- The two list variants also enrich each org with a member count (distinct
-- rbac.user_roles holders) and an MFA-enabled member count (members with a
-- confirmed TOTP / verified OTP factor / push device). These are computed here
-- so the Organizations table shows per-org counts for EVERY org the caller
-- belongs to (the per-organization analytics endpoint is locked to the active org).

-- name: ListOrganizationsForUser :many
SELECT t.id, t.slug, t.name, t.status, t.plan, t.region, t.logo_url,
       t.metadata, t.created_at, t.updated_at, t.deletion_due_at,
  (SELECT count(DISTINCT ur.user_id) FROM rbac.user_roles ur
     WHERE ur.organization_id = t.id)::bigint AS member_count,
  (SELECT count(DISTINCT ur.user_id) FROM rbac.user_roles ur
     WHERE ur.organization_id = t.id
       AND (EXISTS(SELECT 1 FROM auth.mfa_totp mt WHERE mt.user_id = ur.user_id AND mt.confirmed_at IS NOT NULL)
         OR EXISTS(SELECT 1 FROM auth.mfa_otp_factors mo WHERE mo.user_id = ur.user_id AND mo.verified_at IS NOT NULL)
         OR EXISTS(SELECT 1 FROM auth.mfa_push_devices md WHERE md.user_id = ur.user_id)))::bigint AS mfa_enabled_count
FROM organization.organizations t
WHERE t.deleted_at IS NULL
  AND t.id IN (SELECT ur.organization_id FROM rbac.user_roles ur WHERE ur.user_id = $1
               UNION SELECT u.organization_id FROM account.users u WHERE u.id = $1)
ORDER BY t.created_at DESC, t.id DESC
LIMIT $2;

-- name: ListOrganizationsForUserAfter :many
SELECT t.id, t.slug, t.name, t.status, t.plan, t.region, t.logo_url,
       t.metadata, t.created_at, t.updated_at, t.deletion_due_at,
  (SELECT count(DISTINCT ur.user_id) FROM rbac.user_roles ur
     WHERE ur.organization_id = t.id)::bigint AS member_count,
  (SELECT count(DISTINCT ur.user_id) FROM rbac.user_roles ur
     WHERE ur.organization_id = t.id
       AND (EXISTS(SELECT 1 FROM auth.mfa_totp mt WHERE mt.user_id = ur.user_id AND mt.confirmed_at IS NOT NULL)
         OR EXISTS(SELECT 1 FROM auth.mfa_otp_factors mo WHERE mo.user_id = ur.user_id AND mo.verified_at IS NOT NULL)
         OR EXISTS(SELECT 1 FROM auth.mfa_push_devices md WHERE md.user_id = ur.user_id)))::bigint AS mfa_enabled_count
FROM organization.organizations t
WHERE t.deleted_at IS NULL
  AND t.id IN (SELECT ur.organization_id FROM rbac.user_roles ur WHERE ur.user_id = $1
               UNION SELECT u.organization_id FROM account.users u WHERE u.id = $1)
  AND (t.created_at < @before_created_at
       OR (t.created_at = @before_created_at AND t.id < @before_id))
ORDER BY t.created_at DESC, t.id DESC
LIMIT @row_limit;

-- The next four queries are the static, cross-context writes of CreateWithOwner.
-- They target other bounded contexts (rbac.*, account.users) but are fixed SQL with
-- positional binds, so they compile under the shared migration schema and run on the
-- caller's shared pgx.Tx via r.q.WithTx(tx).X(...).

-- name: InsertOwnerRole :one
INSERT INTO rbac.roles (organization_id, name, description, is_system)
VALUES ($1, 'owner', 'Tenant owner — full access', TRUE)
RETURNING id;

-- name: GrantAllPermissionsToRole :exec
INSERT INTO rbac.role_permissions (role_id, permission_id)
SELECT $1, id FROM rbac.permissions;

-- name: InsertBuiltinRoles :exec
-- A new organization's built-in roles, read-only like owner: admin holds
-- everything but deleting the organization, viewer every read but secrets'
-- (whose read reveals them), member nothing.
WITH builtin AS (
    INSERT INTO rbac.roles (organization_id, name, description, is_system)
    VALUES (@organization_id, 'admin', 'Administrator — everything but deleting the organisation', TRUE),
           (@organization_id, 'member', 'Member — signs in to the organisation''s apps, no administration', TRUE),
           (@organization_id, 'viewer', 'Viewer — reads everything, changes nothing', TRUE)
    RETURNING id, name
)
INSERT INTO rbac.role_permissions (role_id, permission_id)
SELECT b.id, p.id FROM builtin b
JOIN rbac.permissions p ON (b.name = 'admin' AND p.key <> 'tenant.delete')
                        OR (b.name = 'viewer' AND p.key LIKE '%.read' AND p.key <> 'secret.read');

-- name: GrantRoleToUser :exec
INSERT INTO rbac.user_roles (user_id, organization_id, role_id, granted_by)
VALUES ($1, $2, $3, $1);

-- name: AdoptHomeOrganization :exec
UPDATE account.users SET organization_id = @organization_id::uuid, updated_at = NOW()
WHERE id = @id AND organization_id IS NULL AND deleted_at IS NULL;
