-- Queries for the users domain.
-- Static queries live here; the partial-UPDATE method (Update) stays hand-written
-- (dbutil.UpdateBuilder builds the SET clause dynamically).
-- CreateWithCredential inserts the user and (optionally) their password credential
-- in one tx; both halves are static and run as sqlc queries on the same pgx.Tx.

-- InsertUser is the user-row half of CreateWithCredential; the cross-context
-- password credential is inserted by InsertPasswordCredential on the same tx.
-- name: InsertUser :one
INSERT INTO "user".users (tenant_id, email, phone, display_name, metadata)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, tenant_id, email, email_verified_at, phone, phone_verified_at,
          display_name, status, metadata, created_at, updated_at;

-- InsertPasswordCredential is the password-credential half of CreateWithCredential.
-- It writes into the auth bounded context but is fixed SQL, so it runs on the shared tx.
-- name: InsertPasswordCredential :exec
INSERT INTO auth.password_credentials (user_id, password_hash)
VALUES ($1, $2);

-- GetUserByID fetches the full user row including avatar_url (read by the
-- profile / header paths that want to render the avatar).
-- name: GetUserByID :one
SELECT id, tenant_id, email, email_verified_at, phone, phone_verified_at,
       display_name, status, metadata, created_at, updated_at, avatar_url
FROM "user".users WHERE id = $1 AND deleted_at IS NULL;

-- GetUserTenantOf returns the tenant a user belongs to regardless of soft-delete
-- (used to enforce that admin by-id operations never cross tenant boundaries).
-- name: GetUserTenantOf :one
SELECT tenant_id FROM "user".users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT id, tenant_id, email, email_verified_at, phone, phone_verified_at,
       display_name, status, metadata, created_at, updated_at
FROM "user".users
WHERE tenant_id = $1 AND LOWER(email) = LOWER($2) AND deleted_at IS NULL;

-- GetUserByEmailGlobal looks up a user by email across all tenants (email is
-- globally unique since migration 0022).
-- name: GetUserByEmailGlobal :one
SELECT id, tenant_id, email, email_verified_at, phone, phone_verified_at,
       display_name, status, metadata, created_at, updated_at
FROM "user".users
WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL;

-- ListUsersByTenant and ListUsersByTenantAfter are left hand-written in
-- repository.go because the COALESCE(array_agg(...), '{}'::text[]) expression
-- causes sqlc to infer Roles as interface{}, making the generated scan
-- unusable. Those two methods continue to use pool.Query with the original SQL.

-- name: SoftDeleteUser :execrows
UPDATE "user".users
SET deleted_at = NOW(), status = 'deleted', updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListDeletedUsers :many
SELECT id, email, display_name, deleted_at, created_at
FROM "user".users
WHERE tenant_id = $1 AND deleted_at IS NOT NULL
ORDER BY deleted_at DESC
LIMIT $2;

-- name: RestoreUser :execrows
UPDATE "user".users
SET deleted_at = NULL, status = 'active', updated_at = NOW()
WHERE id = $1 AND deleted_at IS NOT NULL;

-- name: PurgeUser :execrows
DELETE FROM "user".users WHERE id = $1 AND deleted_at IS NOT NULL;

-- name: MarkEmailVerified :exec
UPDATE "user".users
SET email_verified_at = COALESCE(email_verified_at, NOW()), updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetPasswordHash :one
SELECT password_hash FROM auth.password_credentials WHERE user_id = $1;

-- name: SetPassword :exec
INSERT INTO auth.password_credentials (user_id, password_hash, updated_at)
VALUES ($1, $2, NOW())
ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW();

-- ── User 360 admin reads ──────────────────────────────────────────────────────
-- These power the console's per-user "identity investigation" workspace. They
-- read cross-schema (auth/rbac/tenant) but are fixed SQL, so they live in the
-- users package's sqlc set (whose schema path is the shared migrations dir).
-- Every aggregate / correlated subquery is explicitly cast so sqlc infers a
-- concrete Go type instead of interface{} (see the array_agg note above).

-- GetUserSecuritySummary aggregates a user's authentication posture into one row:
-- MFA factors (TOTP / email-SMS OTP / push), passkeys, recovery codes, whether a
-- password is set, and the active-session/device count. Only non-null count and
-- boolean signals live here so sqlc types them concretely; the two nullable
-- timestamps (password last-changed, passkey last-used) are fetched by the
-- dedicated :one queries below, where an absent row cleanly means "never".
-- name: GetUserSecuritySummary :one
SELECT
  u.mfa_required::boolean AS mfa_required,
  EXISTS(SELECT 1 FROM auth.mfa_totp t WHERE t.user_id = u.id AND t.confirmed_at IS NOT NULL)::boolean AS totp_enabled,
  (SELECT count(*) FROM auth.mfa_otp_factors o WHERE o.user_id = u.id AND o.verified_at IS NOT NULL)::int AS otp_factors,
  (SELECT count(*) FROM auth.mfa_push_devices d WHERE d.user_id = u.id)::int AS push_devices,
  (SELECT count(*) FROM auth.passkey_credentials p WHERE p.user_id = u.id)::int AS passkeys,
  (SELECT count(*) FROM auth.mfa_recovery_codes rc WHERE rc.user_id = u.id AND rc.used_at IS NULL)::int AS recovery_codes_remaining,
  EXISTS(SELECT 1 FROM auth.password_credentials pc WHERE pc.user_id = u.id)::boolean AS password_set,
  (SELECT count(*) FROM auth.sessions s WHERE s.user_id = u.id AND s.revoked_at IS NULL)::int AS active_sessions,
  (SELECT count(DISTINCT s.user_agent) FROM auth.sessions s WHERE s.user_id = u.id AND s.revoked_at IS NULL)::int AS distinct_devices
FROM "user".users u
WHERE u.id = $1 AND u.deleted_at IS NULL;

-- GetUserPasswordChangedAt returns when the user's password was last set/changed.
-- ErrNoRows means the user has no password credential (password login not set up).
-- name: GetUserPasswordChangedAt :one
SELECT updated_at FROM auth.password_credentials WHERE user_id = $1;

-- GetUserPasskeyLastUsed returns the most recent passkey use. Filtering on a
-- non-null last_used_at keeps the scanned value non-null; ErrNoRows means no
-- passkey has ever been used.
-- name: GetUserPasskeyLastUsed :one
SELECT last_used_at FROM auth.passkey_credentials
WHERE user_id = $1 AND last_used_at IS NOT NULL
ORDER BY last_used_at DESC
LIMIT 1;

-- ListUserActiveSessions lists a user's live sessions (most-recently-seen first).
-- ip is rendered through host() (clean address, no INET CIDR suffix) and
-- COALESCEd so the nullable INET scans into a plain non-null string.
-- name: ListUserActiveSessions :many
SELECT id, COALESCE(host(ip), '')::text AS ip, user_agent, created_at, last_seen_at
FROM auth.sessions
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY last_seen_at DESC
LIMIT 100;

-- RevokeAllUserSessions revokes every live session for a user (admin force
-- sign-out). Returns the number of sessions revoked.
-- name: RevokeAllUserSessions :execrows
UPDATE auth.sessions
SET revoked_at = NOW()
WHERE user_id = $1 AND revoked_at IS NULL;

-- ListUserRolesInTenant returns the roles directly assigned to a user within a
-- tenant (group-inherited roles are reflected in effective permissions elsewhere).
-- name: ListUserRolesInTenant :many
SELECT ro.id, ro.name, ro.description
FROM rbac.user_roles ur
JOIN rbac.roles ro ON ro.id = ur.role_id
WHERE ur.user_id = $1 AND ur.tenant_id = $2
ORDER BY ro.name;

-- ListUserGroupsInTenant returns the groups a user belongs to within a tenant.
-- name: ListUserGroupsInTenant :many
SELECT g.id, g.name, g.description
FROM tenant.group_members gm
JOIN tenant.groups g ON g.id = gm.group_id
WHERE gm.user_id = $1 AND gm.tenant_id = $2
ORDER BY g.name;

-- GetUserOrganization returns the tenant (a.k.a. organization) a user belongs to.
-- Each user belongs to exactly one tenant (users.tenant_id is NOT NULL).
-- name: GetUserOrganization :one
SELECT t.id, t.name, t.slug
FROM "user".users u
JOIN tenant.tenants t ON t.id = u.tenant_id
WHERE u.id = $1;

-- CountUserApplications counts the OIDC applications a user has consented to,
-- scoped to the applications registered in the given tenant.
-- name: CountUserApplications :one
SELECT count(*)::int AS applications
FROM auth.oidc_consents c
JOIN auth.oidc_clients oc ON oc.client_id = c.client_id
WHERE c.user_id = $1 AND oc.tenant_id = $2;

-- CountTenantEnabledPolicies counts the tenant's enabled ABAC policies — the
-- access rules that can apply to any member, including this user.
-- name: CountTenantEnabledPolicies :one
SELECT count(*)::int AS policies
FROM auth.abac_policies
WHERE tenant_id = $1 AND enabled = TRUE;

-- CountUserDirectPermissions counts the distinct permissions a user holds via
-- directly-assigned roles (rbac.user_roles) — the "direct" half of the split.
-- name: CountUserDirectPermissions :one
SELECT count(DISTINCT p.key)::int AS direct
FROM rbac.user_roles ur
JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
JOIN rbac.permissions p ON p.id = rp.permission_id
WHERE ur.user_id = $1 AND ur.tenant_id = $2;

-- CountUserEffectivePermissions counts the distinct effective permissions — the
-- union of directly-assigned roles and group-inherited roles. Mirrors the RBAC
-- ListEffectivePermissions query. "inherited" is derived as effective − direct.
-- name: CountUserEffectivePermissions :one
SELECT count(*)::int AS effective FROM (
  SELECT p.key
  FROM rbac.user_roles ur
  JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
  JOIN rbac.permissions p ON p.id = rp.permission_id
  WHERE ur.user_id = $1 AND ur.tenant_id = $2
  UNION
  SELECT p.key
  FROM tenant.group_members gm
  JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
  JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
  JOIN rbac.permissions p ON p.id = rp.permission_id
  WHERE gm.user_id = $1 AND gm.tenant_id = $2
) eff;

-- SetUserMfaRequired flips the users.mfa_required policy flag for a user. Returns
-- the rows affected (0 = user not found / soft-deleted).
-- name: SetUserMfaRequired :execrows
UPDATE "user".users
SET mfa_required = $2, updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL;

-- GetUserStats returns the tenant-wide member counts for the Users admin summary
-- strip: total, active, suspended, invited, and MFA enabled/missing. Membership
-- is defined the same way the list is (an rbac.user_roles row in this tenant),
-- and "MFA enabled" matches the list's OR-logic (confirmed TOTP / verified OTP /
-- a push device).
-- name: GetUserStats :one
WITH members AS (
  SELECT u.id, u.status, u.created_at
  FROM "user".users u
  WHERE u.deleted_at IS NULL
    AND EXISTS (SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.tenant_id = $1)
),
mfa AS (
  SELECT m.id,
    (EXISTS(SELECT 1 FROM auth.mfa_totp t WHERE t.user_id = m.id AND t.confirmed_at IS NOT NULL)
     OR EXISTS(SELECT 1 FROM auth.mfa_otp_factors o WHERE o.user_id = m.id AND o.verified_at IS NOT NULL)
     OR EXISTS(SELECT 1 FROM auth.mfa_push_devices d WHERE d.user_id = m.id)) AS has_mfa
  FROM members m
)
SELECT
  count(*)::int AS total_users,
  (count(*) FILTER (WHERE members.status = 'active'))::int AS active_users,
  (count(*) FILTER (WHERE members.status = 'suspended'))::int AS suspended_users,
  (count(*) FILTER (WHERE members.status = 'invited'))::int AS invited_users,
  (count(*) FILTER (WHERE mfa.has_mfa))::int AS mfa_enabled,
  (count(*) FILTER (WHERE NOT mfa.has_mfa))::int AS mfa_missing,
  (count(*) FILTER (WHERE members.created_at >= now() - interval '30 days'))::int AS new_last_30d
FROM members JOIN mfa USING (id);

-- GetUserTrends returns a 30-day daily series (one row per day, oldest first) for
-- the Users KPI sparklines: cumulative total members and cumulative members with
-- at least one MFA factor enrolled. Both are derived from real timestamps
-- (users.created_at and the earliest MFA factor enrolment); the MFA curve is an
-- enrolment curve (factor removals are not historised, so it never decreases).
-- name: GetUserTrends :many
WITH days AS (
  SELECT generate_series(
    date_trunc('day', now()) - interval '29 days',
    date_trunc('day', now()),
    interval '1 day'
  ) AS day
),
members AS (
  SELECT u.id, u.created_at,
    (SELECT min(e.at) FROM (
       SELECT t.confirmed_at AS at FROM auth.mfa_totp t WHERE t.user_id = u.id AND t.confirmed_at IS NOT NULL
       UNION ALL
       SELECT o.verified_at FROM auth.mfa_otp_factors o WHERE o.user_id = u.id AND o.verified_at IS NOT NULL
       UNION ALL
       SELECT d.created_at FROM auth.mfa_push_devices d WHERE d.user_id = u.id
     ) e) AS mfa_at
  FROM "user".users u
  WHERE u.deleted_at IS NULL
    AND EXISTS (SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.tenant_id = $1)
)
SELECT
  (SELECT count(*) FROM members m WHERE m.created_at < days.day + interval '1 day')::int AS total,
  (SELECT count(*) FROM members m WHERE m.mfa_at IS NOT NULL AND m.mfa_at < days.day + interval '1 day')::int AS mfa
FROM days
ORDER BY days.day;
