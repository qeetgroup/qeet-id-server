-- 0050_mfa_login_challenges — pending 2nd-factor challenge minted after a password login for MFA-enrolled users; exchanged single-use at POST /v1/auth/mfa for a token pair
CREATE TABLE auth.mfa_login_challenges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    tenant_id   UUID,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_mfa_login_chal_user ON auth.mfa_login_challenges (user_id);
