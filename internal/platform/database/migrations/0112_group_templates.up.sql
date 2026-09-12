-- 0112_group_templates — reusable group shapes for the directory.
--
-- A template captures a group structure a tenant creates repeatedly (an
-- engineering org chart, a per-project trio of groups, a regional split) so it
-- can be applied in one action rather than hand-built each time.
--
-- `nodes` is JSONB rather than a child table: a template is applied as a whole,
-- never queried by node, and the shape is a tree whose depth isn't known up
-- front. Each node is {"name": "...", "description": "...", "children": [...]}.
CREATE TABLE tenant.group_templates (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    nodes       JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Template names are how an operator picks one, so keep them unique per tenant.
-- Case-insensitive so "Engineering" and "engineering" can't both exist.
-- (Note: tenant.groups itself does NOT constrain names — this is a property of
-- templates only.)
CREATE UNIQUE INDEX uq_group_templates_tenant_name
    ON tenant.group_templates (tenant_id, LOWER(name));

CREATE INDEX idx_group_templates_tenant ON tenant.group_templates (tenant_id, created_at DESC);

-- No RLS policy: Qeet ID scopes by tenant in the application layer (every query
-- carries tenant_id and handlers check the caller's tenant), and no other table
-- in this schema uses RLS. Adding it here alone would imply a guarantee the
-- rest of the system doesn't make.
