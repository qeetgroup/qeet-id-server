-- Per-tenant secrets vault: named integration secrets (3rd-party API keys,
-- signing material, etc.) stored encrypted at rest (AES-256-GCM). The plaintext
-- is never persisted and is only returned via an explicit, audited reveal.

CREATE TABLE tenant.secrets (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT '',
    ciphertext BYTEA NOT NULL,
    nonce      BYTEA NOT NULL,
    last4      TEXT NOT NULL DEFAULT '',   -- display hint; only set for longer secrets
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_secrets_tenant ON tenant.secrets (tenant_id);
