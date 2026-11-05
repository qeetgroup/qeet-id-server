-- 0230_monthly_active_users — the people active in an organisation each
-- calendar month (UTC), for the plans' monthly-active-user allowance. A person
-- is active in a month when they sign in to the organisation, or renew a
-- session in it, at least once in that month: a sign-in, a session refresh, an
-- application's code exchange or refresh-token grant. API keys, service
-- principals and AI agents are not people and are never recorded. One row per
-- organisation, month and person; kept 13 months (retention's record sweeps).
CREATE TABLE tenant.monthly_active_users (
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    month         DATE NOT NULL,
    user_id       UUID NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, month, user_id),
    CHECK (month = date_trunc('month', month)::date)
);

CREATE INDEX monthly_active_users_month_idx ON tenant.monthly_active_users (month);

ALTER TABLE tenant.monthly_active_users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.monthly_active_users
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
