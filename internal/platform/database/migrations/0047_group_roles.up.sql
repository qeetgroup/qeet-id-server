-- 0047_group_roles — role grants to a group (confers perms on all members; effective = user grants UNION group grants).
-- Mirrors rbac.user_roles with a group principal; tenant_id is carried + FK'd so lookups stay tenant-scoped and grants drop with the tenant.
CREATE TABLE rbac.group_roles (
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    group_id        UUID NOT NULL REFERENCES tenant.groups(id) ON DELETE CASCADE,
    role_id         UUID NOT NULL REFERENCES rbac.roles(id) ON DELETE CASCADE,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by      UUID,
    PRIMARY KEY (group_id, role_id)
);

CREATE INDEX idx_group_roles_tenant ON rbac.group_roles (tenant_id);
CREATE INDEX idx_group_roles_role ON rbac.group_roles (role_id);
