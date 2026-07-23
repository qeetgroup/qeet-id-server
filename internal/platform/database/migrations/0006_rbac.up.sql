-- 0006_rbac — permissions (global) + roles (per-tenant) + user assignments; built-in roles seeded by the app
CREATE TABLE rbac.permissions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key             TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE rbac.roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    is_system       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_roles_tenant_name ON rbac.roles (tenant_id, LOWER(name));

CREATE TABLE rbac.role_permissions (
    role_id         UUID NOT NULL REFERENCES rbac.roles(id) ON DELETE CASCADE,
    permission_id   UUID NOT NULL REFERENCES rbac.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE rbac.user_roles (
    user_id         UUID NOT NULL,
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    role_id         UUID NOT NULL REFERENCES rbac.roles(id) ON DELETE CASCADE,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by      UUID,
    PRIMARY KEY (user_id, tenant_id, role_id)
);

CREATE INDEX idx_user_roles_user_tenant ON rbac.user_roles (user_id, tenant_id);
