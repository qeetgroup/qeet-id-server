-- Pending second-factor login challenges. A row is created when a password
-- login succeeds for an MFA-enrolled user; the client exchanges it (single-use)
-- at POST /v1/auth/mfa for a full token pair once the second-factor code is
-- verified. Short-lived; expired/used rows are removed on use.
CREATE TABLE auth.mfa_login_challenges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    tenant_id   UUID,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_mfa_login_chal_user ON auth.mfa_login_challenges (user_id);
