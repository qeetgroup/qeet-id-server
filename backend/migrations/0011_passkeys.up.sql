-- WebAuthn / passkeys credentials. The crypto handshake (attestation,
-- assertion) is intentionally not implemented yet — these columns capture
-- the fields a future go-webauthn integration needs.
CREATE TABLE auth.passkey_credentials (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    credential_id     BYTEA NOT NULL,
    public_key        BYTEA NOT NULL,
    sign_count        BIGINT NOT NULL DEFAULT 0,
    aaguid            UUID,
    transports        TEXT[],
    name              TEXT,
    last_used_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX uq_passkey_credid ON auth.passkey_credentials (credential_id);
CREATE INDEX idx_passkey_user ON auth.passkey_credentials (user_id);

CREATE TABLE auth.passkey_challenges (
    challenge_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID REFERENCES "user".users(id) ON DELETE CASCADE,
    challenge         BYTEA NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('register', 'authenticate')),
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
