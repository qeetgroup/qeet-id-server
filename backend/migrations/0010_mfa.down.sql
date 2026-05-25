ALTER TABLE "user".users DROP COLUMN IF EXISTS mfa_required;
DROP TABLE IF EXISTS auth.mfa_recovery_codes;
DROP TABLE IF EXISTS auth.mfa_totp;
