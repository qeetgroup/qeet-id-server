-- Queries for the abac (attribute-based access control) domain.
-- Every statement here is a fixed-shape SQL: the condition tree is evaluated in
-- Go (not in SQL), so both the CRUD statements and the Evaluate candidate load
-- are static SELECTs/INSERT/UPDATE/DELETE and convert cleanly. Nothing in this
-- module builds SQL dynamically.

-- name: CreateAbacPolicy :one
INSERT INTO auth.abac_policies
    (tenant_id, name, description, effect, resource_type, action, condition, priority, enabled)
VALUES (@tenant_id, @name, @description, @effect, @resource_type, @action, sqlc.arg(condition)::jsonb, @priority, @enabled)
RETURNING id, tenant_id, name, description, effect, resource_type, action, condition, priority, enabled, created_at, updated_at;

-- name: GetAbacPolicy :one
SELECT id, tenant_id, name, description, effect, resource_type, action, condition, priority, enabled, created_at, updated_at
FROM auth.abac_policies
WHERE id = @id AND tenant_id = @tenant_id;

-- name: ListAbacPolicies :many
SELECT id, tenant_id, name, description, effect, resource_type, action, condition, priority, enabled, created_at, updated_at
FROM auth.abac_policies
WHERE tenant_id = @tenant_id
ORDER BY priority DESC, name;

-- name: UpdateAbacPolicy :one
UPDATE auth.abac_policies
SET name = @name, description = @description, effect = @effect,
    resource_type = @resource_type, action = @action, condition = sqlc.arg(condition)::jsonb,
    priority = @priority, enabled = @enabled, updated_at = now()
WHERE id = @id AND tenant_id = @tenant_id
RETURNING id, tenant_id, name, description, effect, resource_type, action, condition, priority, enabled, created_at, updated_at;

-- name: DeleteAbacPolicy :one
DELETE FROM auth.abac_policies
WHERE id = @id AND tenant_id = @tenant_id
RETURNING name;

-- name: ListEvaluationCandidates :many
SELECT id, name, effect, condition, priority
FROM auth.abac_policies
WHERE tenant_id = @tenant_id
  AND enabled = true
  AND (resource_type = @resource_type OR resource_type = '*')
  AND (action = @action OR action = '*')
ORDER BY priority DESC;
