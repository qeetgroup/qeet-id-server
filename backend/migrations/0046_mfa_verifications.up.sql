-- Step-up MFA: the latest successful second-factor verification per user.
-- A sensitive action can require a recent row here (any factor — TOTP, recovery
-- code, email/SMS OTP, or a WebAuthn assertion — satisfies step-up). One row per
-- user; each successful verification UPSERTs verified_at = now().
CREATE TABLE auth.mfa_verifications (
    user_id     UUID PRIMARY KEY REFERENCES "user".users(id) ON DELETE CASCADE,
    method      TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
