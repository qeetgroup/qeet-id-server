-- 0029_scim — SCIM 2.0 provisioning: one bearer token per tenant (presented by its IdP) + provisioned-via tagging on users

ALTER TABLE "user".users
    ADD COLUMN IF NOT EXISTS external_id     TEXT,
    ADD COLUMN IF NOT EXISTS provisioned_via TEXT;

-- One token per tenant (rotate = upsert on tenant_id); only the token's SHA-256 is stored, plus a display-only prefix.
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
