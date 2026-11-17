-- 0250_login_code_issuers — a SAML or social one-time login code records the connection or the
-- provider that issued it, so trading the code re-checks that it is still switched on, as OpenID
-- Connect codes do. A code from before this migration names neither and no longer trades; codes
-- last five minutes.
ALTER TABLE auth.saml_login_codes ADD COLUMN IF NOT EXISTS connection_id UUID;
ALTER TABLE auth.social_login_codes ADD COLUMN IF NOT EXISTS provider TEXT;
