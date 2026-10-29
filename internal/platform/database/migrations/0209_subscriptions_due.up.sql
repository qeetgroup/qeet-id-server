-- 0209_subscriptions_due — the period-end job finds the subscriptions whose
-- trial or period has ended by when it ends.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_subscriptions_due ON tenant.subscriptions (current_period_end)
    WHERE status IN ('active', 'past_due', 'trialing');
