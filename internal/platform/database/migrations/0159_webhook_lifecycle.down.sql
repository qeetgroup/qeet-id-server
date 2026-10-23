ALTER TABLE tenant.webhook_subscriptions
    DROP CONSTRAINT webhook_previous_secret_complete,
    DROP COLUMN previous_secret_expires_at,
    DROP COLUMN previous_secret_nonce,
    DROP COLUMN previous_secret_ct,
    DROP COLUMN disabled_reason,
    DROP COLUMN failing_since;
