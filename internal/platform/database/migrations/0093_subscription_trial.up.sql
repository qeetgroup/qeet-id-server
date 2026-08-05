-- 0093_subscription_trial — no-card free trial support.
-- trial_end marks when a `status = 'trialing'` subscription reverts to free if it
-- hasn't converted to paid. Expiry is evaluated lazily by the entitlements
-- resolver (a trial past trial_end grants nothing), so no scheduler is required.
ALTER TABLE tenant.subscriptions ADD COLUMN trial_end TIMESTAMPTZ;
