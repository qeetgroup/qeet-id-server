-- 0226_abac_policies_tenant_id_id — a unique (tenant_id, id) on ABAC policies,
-- so a policy's saved versions refer to it by both and the database refuses a
-- version naming another organisation's policy.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS abac_policies_tenant_id_id_key
    ON auth.abac_policies (tenant_id, id);
