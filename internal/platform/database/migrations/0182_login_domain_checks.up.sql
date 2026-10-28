-- 0182_login_domain_checks — the last check of an organisation's sign-in
-- address, kept instead of run on every read.
--
-- GET /login-domain looked up its DNS records and probed its certificate and
-- the hosted login on every page load, and kept no time of the check. The last
-- check's result and time are kept here; a separate call runs a new one.
CREATE TABLE tenant.login_domain_checks (
    tenant_id  UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    host       TEXT        NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL,
    result     JSONB       NOT NULL
);

ALTER TABLE tenant.login_domain_checks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.login_domain_checks
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
