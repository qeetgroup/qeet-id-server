-- 0068_auth_hook_claims — persist auth-hook claims on the pending MFA challenge: the hook runs at password-verify, but token issuance happens after the 2nd factor, so the claims must survive in between
ALTER TABLE auth.mfa_login_challenges ADD COLUMN IF NOT EXISTS claims JSONB;
