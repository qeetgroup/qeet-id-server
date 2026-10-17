-- 0134_push_pairing_codes — a phone is linked with a one-time pairing code
-- instead of a copied access token.
--
-- auth.mfa_push_pairings: a code a signed-in person asked for to link a phone
-- to their account. Only its SHA-256 is kept (code_hash). It links one phone,
-- once (used_at, device_id), before expires_at; asking for a new code expires
-- the person's earlier unused ones. tenant_id is the organisation the person
-- was signed in to when they asked, for the audit trail.
CREATE TABLE IF NOT EXISTS auth.mfa_push_pairings (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    tenant_id  UUID        REFERENCES tenant.tenants(id) ON DELETE SET NULL,
    code_hash  TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    device_id  UUID        REFERENCES auth.mfa_push_devices(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS mfa_push_pairings_user ON auth.mfa_push_pairings (user_id, created_at);
CREATE INDEX IF NOT EXISTS mfa_push_pairings_expires ON auth.mfa_push_pairings (expires_at);
