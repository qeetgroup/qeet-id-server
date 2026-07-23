-- 0010_mfa — TOTP secrets + recovery codes; users.mfa_required flag
CREATE TABLE auth.mfa_totp (
    user_id        UUID PRIMARY KEY REFERENCES "user".users(id) ON DELETE CASCADE,
    secret         TEXT NOT NULL,        -- base32, encrypt-at-rest in prod
    confirmed_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.mfa_recovery_codes (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    code_hash      TEXT NOT NULL,
    used_at        TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_mfa_recovery_user ON auth.mfa_recovery_codes (user_id);

ALTER TABLE "user".users ADD COLUMN mfa_required BOOLEAN NOT NULL DEFAULT FALSE;
