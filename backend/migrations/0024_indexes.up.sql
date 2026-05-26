-- Indexes covering hot query paths that the existing migrations missed.
-- See IMPROVEMENTS.md §3.1 for the rationale per index.

-- "What did user X do?" — audit log filter by actor.
CREATE INDEX idx_audit_actor
    ON audit.events (actor_user_id, created_at DESC)
    WHERE actor_user_id IS NOT NULL;

-- "How many active sessions for tenant T?" / per-tenant session list.
-- The existing idx_sessions_active is keyed by user_id; admin-facing
-- queries filter by tenant first.
CREATE INDEX idx_sessions_tenant_active
    ON auth.sessions (tenant_id)
    WHERE revoked_at IS NULL;

-- Janitor cleanup of expired password resets.
CREATE INDEX idx_password_resets_expires
    ON auth.password_resets (expires_at)
    WHERE used_at IS NULL;

-- Janitor cleanup of expired magic links.
CREATE INDEX idx_magic_links_expires
    ON auth.magic_links (expires_at)
    WHERE used_at IS NULL;

-- Webhook dispatcher hot path: pick pending deliveries for a specific
-- subscription. The existing idx_webhook_deliv_pending is keyed only by
-- next_attempt_at and scans across all subscriptions.
CREATE INDEX idx_webhook_deliveries_sub_pending
    ON tenant.webhook_deliveries (subscription_id, next_attempt_at)
    WHERE delivered_at IS NULL;
