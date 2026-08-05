-- 0090_tenant_plan_check — pin tenant.tenants.plan to the known self-serve tiers.
-- The column was free-text (no CHECK/FK), so it could drift to any value. This
-- constrains it to the catalogue tiers, matching the CreateInput/UpdateInput
-- validation and the entitlements catalog. Annual "_year" variants live on the
-- subscription, never here (billing writes the stripped base tier).

-- Normalize first so the constraint can't fail on an existing row at startup:
-- strip any annual suffix, then coerce anything unrecognized to 'free'.
UPDATE tenant.tenants SET plan = regexp_replace(plan, '_year$', '');
UPDATE tenant.tenants SET plan = 'free'
    WHERE plan NOT IN ('free', 'starter', 'pro', 'enterprise');

ALTER TABLE tenant.tenants
    ADD CONSTRAINT tenants_plan_check
    CHECK (plan IN ('free', 'starter', 'pro', 'enterprise'));
