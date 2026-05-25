-- Optional org/team hierarchy inside a tenant. Memberships bind users to
-- groups; permissions can later be granted at group level.
CREATE TABLE tenant.groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    parent_id       UUID REFERENCES tenant.groups(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_groups_tenant ON tenant.groups (tenant_id);
CREATE INDEX idx_groups_parent ON tenant.groups (parent_id);

CREATE TABLE tenant.group_members (
    group_id        UUID NOT NULL REFERENCES tenant.groups(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL,
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, user_id)
);
