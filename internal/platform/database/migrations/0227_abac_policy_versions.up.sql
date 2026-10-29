-- 0227_abac_policy_versions — every save of an ABAC policy, whole, with who
-- made it, numbered from 1, so one can be compared and restored. The policy
-- carries its current version and who saved it last. Each existing policy's
-- current state is kept as its version 1.
ALTER TABLE auth.abac_policies
    ADD COLUMN IF NOT EXISTS version    INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS updated_by UUID;

CREATE TABLE auth.abac_policy_versions (
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    policy_id     UUID NOT NULL,
    version       INT NOT NULL CHECK (version >= 1),
    name          TEXT NOT NULL,
    description   TEXT NOT NULL,
    effect        TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    action        TEXT NOT NULL,
    condition     JSONB NOT NULL,
    priority      INT NOT NULL,
    enabled       BOOLEAN NOT NULL,
    saved_by      UUID,
    saved_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, policy_id, version),
    FOREIGN KEY (tenant_id, policy_id) REFERENCES auth.abac_policies (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE auth.abac_policy_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.abac_policy_versions
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

INSERT INTO auth.abac_policy_versions
    (tenant_id, policy_id, version, name, description, effect, resource_type, action, condition, priority, enabled, saved_at)
SELECT tenant_id, id, 1, name, description, effect, resource_type, action, condition, priority, enabled, updated_at
FROM auth.abac_policies;
