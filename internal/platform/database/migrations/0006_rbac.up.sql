-- 0006_rbac — roles, permissions and who holds which role in which
-- organisation.
--
-- Each table is headed by the package that owns it. A column marked (0010) is a
-- foreign key into another schema, which 0010_cross_schema_keys adds.

-- internal/access/authorization/rbac
CREATE TABLE rbac.permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key         TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

-- internal/access/authorization/rbac
CREATE TABLE rbac.roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL, -- tenant.tenants (0010)
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX uq_roles_tenant_name ON rbac.roles (tenant_id, lower(name));

-- internal/access/authorization/accessrequest
CREATE TABLE rbac.access_requests (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL, -- tenant.tenants (0010)
    requester_id   UUID NOT NULL,
    role_id        UUID NOT NULL,
    reason         TEXT NOT NULL,
    duration_hours INTEGER,
    status         TEXT NOT NULL DEFAULT 'pending',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ NOT NULL,
    decided_by     UUID,
    decided_at     TIMESTAMPTZ,
    decision_note  TEXT,
    granted        BOOLEAN NOT NULL DEFAULT FALSE,
    access_ends_at TIMESTAMPTZ,
    ended_at       TIMESTAMPTZ,
    CONSTRAINT access_requests_tenant_id_role_id_fkey FOREIGN KEY (tenant_id, role_id)
        REFERENCES rbac.roles (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT access_requests_check CHECK (
        status <> 'denied'
        OR (decision_note IS NOT NULL AND decision_note <> '')),
    CONSTRAINT access_requests_check1 CHECK ((status IN ('approved', 'denied')) = (decided_at IS NOT NULL)),
    CONSTRAINT access_requests_decision_note_check CHECK (
        decision_note IS NULL
        OR char_length(decision_note) <= 500),
    CONSTRAINT access_requests_duration_hours_check CHECK (
        duration_hours IS NULL
        OR (duration_hours >= 1 AND duration_hours <= 2160)),
    CONSTRAINT access_requests_reason_check CHECK (char_length(reason) >= 1 AND char_length(reason) <= 500),
    CONSTRAINT access_requests_status_check CHECK (status IN (
            'pending', 'approved', 'denied', 'cancelled', 'expired'))
);
CREATE INDEX access_requests_ending_idx ON rbac.access_requests (access_ends_at)
    WHERE status = 'approved' AND granted AND ended_at IS NULL;
CREATE INDEX access_requests_lapsing_idx ON rbac.access_requests (expires_at) WHERE status = 'pending';
CREATE UNIQUE INDEX access_requests_one_pending_idx ON rbac.access_requests (tenant_id, requester_id, role_id)
    WHERE status = 'pending';
CREATE INDEX access_requests_requester_idx ON rbac.access_requests (requester_id, tenant_id, created_at DESC);
CREATE INDEX access_requests_tenant_idx ON rbac.access_requests (tenant_id, status, created_at DESC, id DESC);

-- internal/access/authorization/rbac
CREATE TABLE rbac.group_roles (
    tenant_id  UUID NOT NULL, -- tenant.groups, tenant.tenants (0010)
    group_id   UUID NOT NULL, -- tenant.groups (0010)
    role_id    UUID NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by UUID,
    PRIMARY KEY (group_id, role_id),
    CONSTRAINT group_roles_role_id_fkey FOREIGN KEY (tenant_id, role_id)
        REFERENCES rbac.roles (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_group_roles_role ON rbac.group_roles (role_id);
CREATE INDEX idx_group_roles_tenant ON rbac.group_roles (tenant_id);

-- internal/access/authorization/rbac
CREATE TABLE rbac.role_permissions (
    role_id       UUID NOT NULL REFERENCES rbac.roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES rbac.permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- internal/access/authorization/rbac
CREATE TABLE rbac.user_roles (
    user_id    UUID NOT NULL, -- account.users (0010)
    tenant_id  UUID NOT NULL, -- tenant.tenants (0010)
    role_id    UUID NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by UUID,
    PRIMARY KEY (user_id, tenant_id, role_id),
    CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (tenant_id, role_id)
        REFERENCES rbac.roles (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_user_roles_tenant ON rbac.user_roles (tenant_id, user_id);
