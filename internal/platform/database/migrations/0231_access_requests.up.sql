-- 0231_access_requests — a person asking an organisation for a role, for a
-- while or for good, and an administrator's answer. A pending request lapses
-- after its expires_at. An approved request with access_ends_at gave the role
-- for a while: when granted is true the role was added by this request, and a
-- maintenance job takes it back at access_ends_at (ended_at records when). A
-- role the person already held is never taken back by a request.
CREATE TABLE rbac.access_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    requester_id    UUID NOT NULL,
    role_id         UUID NOT NULL,
    reason          TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500),
    -- NULL: for good. Otherwise up to 90 days.
    duration_hours  INTEGER CHECK (duration_hours IS NULL OR duration_hours BETWEEN 1 AND 2160),
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'denied', 'cancelled', 'expired')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    decided_by      UUID,
    decided_at      TIMESTAMPTZ,
    decision_note   TEXT CHECK (decision_note IS NULL OR char_length(decision_note) <= 500),
    granted         BOOLEAN NOT NULL DEFAULT FALSE,
    access_ends_at  TIMESTAMPTZ,
    ended_at        TIMESTAMPTZ,
    CHECK (status <> 'denied' OR (decision_note IS NOT NULL AND decision_note <> '')),
    CHECK ((status IN ('approved', 'denied')) = (decided_at IS NOT NULL)),
    -- The role is the organisation's own: referred to by (tenant_id, id).
    FOREIGN KEY (tenant_id, role_id) REFERENCES rbac.roles (tenant_id, id) ON DELETE CASCADE
);

-- One request waiting per person and role.
CREATE UNIQUE INDEX access_requests_one_pending_idx
    ON rbac.access_requests (tenant_id, requester_id, role_id) WHERE status = 'pending';
CREATE INDEX access_requests_tenant_idx ON rbac.access_requests (tenant_id, status, created_at DESC, id DESC);
CREATE INDEX access_requests_requester_idx ON rbac.access_requests (requester_id, tenant_id, created_at DESC);
-- The maintenance job's two sweeps.
CREATE INDEX access_requests_ending_idx ON rbac.access_requests (access_ends_at)
    WHERE status = 'approved' AND granted AND ended_at IS NULL;
CREATE INDEX access_requests_lapsing_idx ON rbac.access_requests (expires_at) WHERE status = 'pending';

ALTER TABLE rbac.access_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rbac.access_requests
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
