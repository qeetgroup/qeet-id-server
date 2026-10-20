-- 0144_oidc_resources — the downstream services a token may be issued for.
--
-- A client could name any resource (RFC 8707) and receive a Qeet-signed token
-- with that name added to its audience, alongside the platform's, so a token
-- minted for one service was accepted by every other service and by the
-- platform API. An organisation now registers the resources its tokens may be
-- issued for; a token for one is issued for it alone. server_client_id is the
-- application that serves the resource, which may introspect tokens issued
-- for it (NULL: none).
CREATE TABLE auth.oidc_resources (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    identifier       TEXT NOT NULL,
    name             TEXT NOT NULL DEFAULT '',
    server_client_id TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, identifier)
);

-- The resource an authorization request named, carried to the code and the
-- consent request so the token is issued for it.
ALTER TABLE auth.oidc_authorization_codes ADD COLUMN resource TEXT;
ALTER TABLE auth.oidc_consent_requests ADD COLUMN resource TEXT NOT NULL DEFAULT '';
