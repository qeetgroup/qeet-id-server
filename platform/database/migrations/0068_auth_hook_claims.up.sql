-- Carry auth-hook-issued custom claims across the MFA step: the hook runs once
-- at password-verify time (CheckPassword), but token issuance for an
-- MFA-enrolled user happens later, after the second factor is confirmed — so
-- the claims a hook returned need to survive in the pending challenge row.
ALTER TABLE auth.mfa_login_challenges ADD COLUMN IF NOT EXISTS claims JSONB;
