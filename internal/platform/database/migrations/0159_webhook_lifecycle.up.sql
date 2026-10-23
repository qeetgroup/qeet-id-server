-- 0159_webhook_lifecycle — a webhook subscription that keeps failing is
-- disabled, and its signing secret can be replaced without a gap.
--
-- failing_since is when deliveries to the endpoint started failing, cleared by
-- a success; disabled_reason says whether an administrator or the failures
-- disabled it. A rotated secret keeps signing alongside the new one until
-- previous_secret_expires_at, so a receiver can switch over.
ALTER TABLE tenant.webhook_subscriptions
    ADD COLUMN failing_since TIMESTAMPTZ,
    ADD COLUMN disabled_reason TEXT CHECK (disabled_reason IN ('disabled', 'failing')),
    ADD COLUMN previous_secret_ct BYTEA,
    ADD COLUMN previous_secret_nonce BYTEA,
    ADD COLUMN previous_secret_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT webhook_previous_secret_complete CHECK (
        (previous_secret_ct IS NULL) = (previous_secret_nonce IS NULL)
        AND (previous_secret_ct IS NULL) = (previous_secret_expires_at IS NULL)
    );

UPDATE tenant.webhook_subscriptions SET disabled_reason = 'disabled' WHERE disabled_at IS NOT NULL;
