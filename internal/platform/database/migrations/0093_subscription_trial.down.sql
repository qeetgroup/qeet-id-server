-- 0093_subscription_trial (down)
ALTER TABLE tenant.subscriptions DROP COLUMN IF EXISTS trial_end;
