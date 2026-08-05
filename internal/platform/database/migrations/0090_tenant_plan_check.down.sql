-- 0090_tenant_plan_check (down) — drop the plan tier constraint.
ALTER TABLE tenant.tenants DROP CONSTRAINT IF EXISTS tenants_plan_check;
