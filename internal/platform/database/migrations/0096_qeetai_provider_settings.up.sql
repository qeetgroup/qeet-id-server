-- 0096_qeetai_provider_settings — per-tenant "bring your own key" (BYOK) AI
-- provider config for the qeetai. One row per tenant; the API key is encrypted
-- at rest with the same AES-256-GCM data key as tenant.secrets (never persisted
-- in plaintext, never returned to the client). When a tenant has an enabled row
-- the qeetai uses their provider/key; otherwise it falls back to the
-- deployment-level QEETAI_* env config.

CREATE TABLE qeetai.provider_settings (
    tenant_id      uuid        NOT NULL PRIMARY KEY REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    provider       text        NOT NULL CHECK (provider IN ('anthropic', 'openai', 'azure')),
    model          text        NOT NULL,
    base_url       text        NOT NULL DEFAULT '',
    max_tokens     integer     NOT NULL DEFAULT 4096 CHECK (max_tokens > 0 AND max_tokens <= 200000),
    key_ciphertext bytea       NOT NULL,
    key_nonce      bytea       NOT NULL,
    key_last4      text        NOT NULL DEFAULT '',   -- display hint; only set for longer keys
    enabled        boolean     NOT NULL DEFAULT true,
    updated_by     uuid,                              -- user who last changed it (nullable)
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
