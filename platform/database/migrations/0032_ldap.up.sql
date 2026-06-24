-- LDAP / Active Directory connections. Users authenticate with username +
-- password: Qeet ID binds with the service account, searches for the user,
-- then re-binds as that user to verify the password, JIT-provisioning a user.
--
-- bind_password is the service-account secret; it is never returned by the API
-- (write-only) and is required in plaintext to bind, so it is stored as-is.

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
