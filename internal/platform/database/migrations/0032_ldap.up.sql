-- 0032_ldap — LDAP/AD connections: bind as the service account, find the user, re-bind as them to verify the password (JIT-provision).
-- bind_password is write-only and stored as-is (plaintext is required to bind).

CREATE TABLE tenant.ldap_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    server_url      TEXT NOT NULL,                       -- ldaps://host:636 or ldap://host:389
    start_tls       BOOLEAN NOT NULL DEFAULT FALSE,       -- upgrade an ldap:// conn via StartTLS
    skip_tls_verify BOOLEAN NOT NULL DEFAULT FALSE,       -- accept self-signed (lab only)
    bind_dn         TEXT NOT NULL,
    bind_password   TEXT NOT NULL,
    base_dn         TEXT NOT NULL,                        -- user search base
    user_filter     TEXT NOT NULL DEFAULT '(uid=%s)',     -- %s := escaped username
    email_attribute TEXT NOT NULL DEFAULT 'mail',
    name_attribute  TEXT NOT NULL DEFAULT 'cn',
    status          TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'active', 'disabled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);
CREATE INDEX idx_ldap_conn_tenant ON tenant.ldap_connections (tenant_id);
