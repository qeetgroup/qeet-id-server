-- SCIM 2.0 provisioning. Each tenant gets one bearer token its IdP (Okta,
-- Entra ID, Google) presents to the /scim/v2 endpoints. Users created or
-- deprovisioned over SCIM are tagged so they can be listed back distinctly
-- from interactively-created users.

ALTER TABLE "user".users
    ADD COLUMN IF NOT EXISTS external_id     TEXT,
    ADD COLUMN IF NOT EXISTS provisioned_via TEXT;

-- One SCIM token per tenant; rotating replaces the row (upsert on tenant_id).
-- We store only the SHA-256 of the token (same scheme as password-reset /
-- magic-link tokens in platform/codes) plus a display-only prefix.
CREATE TABLE tenant.scim_tokens (
    tenant_id     UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL,
    token_prefix  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ
);

-- Resolving a presented token to its tenant is a hash lookup on every SCIM call.
CREATE UNIQUE INDEX uq_scim_token_hash ON tenant.scim_tokens (token_hash);

-- SCIM sync looks users up by (tenant, external_id) and lists provisioned users.
CREATE INDEX idx_users_scim_external
    ON "user".users (tenant_id, external_id)
    WHERE provisioned_via = 'scim' AND deleted_at IS NULL;
