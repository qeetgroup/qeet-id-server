-- Email / SMS one-time-passcode MFA factors. A user registers a channel
-- (email or phone), confirms ownership with a code, then receives OTP
-- challenges on that channel as a second factor. Delivery goes through the
-- notifier.Sender abstraction (LogSender in dev, a real provider in prod).

CREATE TABLE auth.mfa_otp_factors (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    channel     TEXT NOT NULL CHECK (channel IN ('email', 'sms')),
    destination TEXT NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, channel, destination)
);
CREATE INDEX idx_mfa_otp_factors_user ON auth.mfa_otp_factors (user_id);

CREATE TABLE auth.mfa_otp_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    factor_id  UUID NOT NULL REFERENCES auth.mfa_otp_factors(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_mfa_otp_codes_pending
    ON auth.mfa_otp_codes (factor_id) WHERE used_at IS NULL;
