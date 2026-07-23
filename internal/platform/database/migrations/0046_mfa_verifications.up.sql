-- 0046_mfa_verifications — step-up MFA: latest successful second-factor per user (any factor); a sensitive action requires a recent row (upsert on verify)
CREATE TABLE auth.mfa_verifications (
    user_id     UUID PRIMARY KEY REFERENCES "user".users(id) ON DELETE CASCADE,
    method      TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
