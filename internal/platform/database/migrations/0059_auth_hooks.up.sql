-- 0059_auth_hooks — synchronous post-login policy webhook (Qeet POSTs a signed event; the hook allows/denies).
-- fail_open (default true) = logins keep working if the hook errors/times out; false hard-fails (deny) for stricter tenants.
CREATE TABLE tenant.auth_hooks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    trigger     TEXT NOT NULL DEFAULT 'post_login',
    url         TEXT NOT NULL,
    secret      TEXT NOT NULL DEFAULT '',  -- HMAC-SHA256 signing key (write-only)
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    fail_open   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_hooks_tenant ON tenant.auth_hooks (tenant_id);
