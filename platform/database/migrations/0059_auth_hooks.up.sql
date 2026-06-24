-- Auth Actions/Hooks: a tenant plugs a synchronous policy endpoint into the
-- login flow. After credentials verify, Qeet POSTs a signed event to the hook
-- URL; the hook may allow or deny the sign-in. fail_open (default true) decides
-- what happens when the hook errors/times out — true keeps logins working
-- during a hook outage; false hard-fails (deny) for stricter tenants.
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
