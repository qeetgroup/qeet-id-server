-- 0228_authz_decisions — the access decisions an organisation asked of the
-- check, relationship check, AuthZEN and ABAC evaluate calls: who asked, about
-- whom, which resource and action, the answer and what decided it. Kept 30
-- days (retention's record sweeps).
CREATE TABLE auth.authz_decisions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    decided_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source        TEXT NOT NULL CHECK (source IN ('check', 'relation_check', 'authzen', 'abac_evaluate', 'abac_draft')),
    caller_type   TEXT NOT NULL DEFAULT '',
    caller_id     UUID,
    caller_client TEXT NOT NULL DEFAULT '',
    subject       TEXT NOT NULL,
    resource      TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL DEFAULT '',
    allowed       BOOLEAN NOT NULL,
    model         TEXT NOT NULL DEFAULT '',
    rule          TEXT NOT NULL DEFAULT '',
    reason_code   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX authz_decisions_tenant_idx ON auth.authz_decisions (tenant_id, decided_at DESC, id DESC);
CREATE INDEX authz_decisions_decided_idx ON auth.authz_decisions (decided_at);

ALTER TABLE auth.authz_decisions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.authz_decisions
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
