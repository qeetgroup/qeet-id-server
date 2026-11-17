-- Queries for the abac (attribute-based access control) domain.
-- Every statement here is a fixed-shape SQL: the condition tree is evaluated in
-- Go (not in SQL), so both the CRUD statements and the Evaluate candidate load
-- are static SELECTs/INSERT/UPDATE/DELETE and convert cleanly. Nothing in this
-- module builds SQL dynamically.

-- name: CreateAbacPolicy :one
INSERT INTO auth.abac_policies
    (organization_id, name, description, effect, resource_type, action, condition, priority, enabled, updated_by)
VALUES (@organization_id, @name, @description, @effect, @resource_type, @action, sqlc.arg(condition)::jsonb, @priority, @enabled, sqlc.narg('updated_by'))
RETURNING id, organization_id, name, description, effect, resource_type, action, condition, priority, enabled, created_at, updated_at, version, updated_by;

-- name: GetAbacPolicy :one
SELECT id, organization_id, name, description, effect, resource_type, action, condition, priority, enabled, created_at, updated_at, version, updated_by
FROM auth.abac_policies
WHERE id = @id AND organization_id = @organization_id;

-- name: ListAbacPolicies :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, name, description, effect, resource_type, action, condition, priority, enabled, created_at, updated_at, version, updated_by
FROM auth.abac_policies
WHERE organization_id = @organization_id
ORDER BY priority DESC, name
LIMIT 1001;

-- name: UpdateAbacPolicy :one
UPDATE auth.abac_policies
SET name = @name, description = @description, effect = @effect,
    resource_type = @resource_type, action = @action, condition = sqlc.arg(condition)::jsonb,
    priority = @priority, enabled = @enabled, updated_at = now(),
    version = version + 1, updated_by = sqlc.narg('updated_by')
WHERE id = @id AND organization_id = @organization_id
RETURNING id, organization_id, name, description, effect, resource_type, action, condition, priority, enabled, created_at, updated_at, version, updated_by;

-- SaveAbacPolicyVersion keeps a policy's state as saved, as its version.
-- name: SaveAbacPolicyVersion :exec
INSERT INTO auth.abac_policy_versions
    (organization_id, policy_id, version, name, description, effect, resource_type, action, condition, priority, enabled, saved_by)
SELECT p.organization_id, p.id, p.version, p.name, p.description, p.effect, p.resource_type, p.action, p.condition, p.priority, p.enabled, p.updated_by
FROM auth.abac_policies p
WHERE p.id = @id AND p.organization_id = @organization_id;

-- name: ListAbacPolicyVersions :many
-- A policy's saved versions, newest first.
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT version, name, description, effect, resource_type, action, condition, priority, enabled, saved_by, saved_at
FROM auth.abac_policy_versions
WHERE policy_id = @policy_id AND organization_id = @organization_id
ORDER BY version DESC
LIMIT 1001;

-- name: GetAbacPolicyVersion :one
SELECT version, name, description, effect, resource_type, action, condition, priority, enabled, saved_by, saved_at
FROM auth.abac_policy_versions
WHERE policy_id = @policy_id AND organization_id = @organization_id AND version = @version;

-- name: DeleteAbacPolicy :one
DELETE FROM auth.abac_policies
WHERE id = @id AND organization_id = @organization_id
RETURNING name;

-- name: ListEvaluationCandidates :many
SELECT id, name, effect, condition, priority
FROM auth.abac_policies
WHERE organization_id = @organization_id
  AND enabled = true
  AND (resource_type = @resource_type OR resource_type = '*')
  AND (action = @action OR action = '*')
ORDER BY priority DESC;

-- ListSubjectMemberships is what the platform knows of a person in an
-- organization for its policies: the groups they belong to and the roles they
-- hold there, directly or through a group, by name.
-- name: ListSubjectMemberships :many
SELECT 'group'::text AS kind, g.name
FROM organization.group_members gm
JOIN organization.groups g ON g.id = gm.group_id AND g.organization_id = gm.organization_id
WHERE gm.organization_id = @organization_id AND gm.user_id = @user_id
UNION
SELECT 'role'::text AS kind, ro.name
FROM rbac.user_roles ur
JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.organization_id = ur.organization_id
WHERE ur.organization_id = @organization_id AND ur.user_id = @user_id
UNION
SELECT 'role'::text AS kind, ro.name
FROM organization.group_members gm
JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.organization_id = gr.organization_id
WHERE gm.organization_id = @organization_id AND gm.user_id = @user_id
ORDER BY kind, name;

-- SessionSecondFactorMet reports whether a person's live session in an
-- organization met a second factor as the organization's MFA requirement
-- counts one (a challenge, a passkey, a remembered device), or holds a step-up
-- still inside its window. No row: no such session.
-- name: SessionSecondFactorMet :one
SELECT (s.second_factor IS NOT NULL OR EXISTS (
           SELECT 1 FROM auth.mfa_verifications v
           WHERE v.session_id = s.id
             AND v.verified_at > NOW() - COALESCE(sp.step_up_window, INTERVAL '5 minutes')
       ))::bool AS met
FROM auth.sessions s
LEFT JOIN organization.security_policies sp ON sp.organization_id = s.organization_id
WHERE s.id = @session_id AND s.user_id = @user_id AND s.organization_id = @organization_id::uuid
  AND s.revoked_at IS NULL AND s.expires_at > NOW();

-- name: CountEnabledPolicies :one
-- How many enabled deny and allow policies an organization has, so a decision can
-- skip ABAC for an organization with none of the kind it needs.
SELECT count(*) FILTER (WHERE effect = 'deny')::int  AS deny,
       count(*) FILTER (WHERE effect = 'allow')::int AS allow
FROM auth.abac_policies
WHERE organization_id = @organization_id AND enabled = true;
