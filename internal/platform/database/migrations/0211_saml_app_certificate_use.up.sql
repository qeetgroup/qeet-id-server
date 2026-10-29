-- 0211_saml_app_certificate_use — what a SAML app's certificate is for:
-- verifying the sign-in requests the app signs, encrypting the assertions sent
-- to it, or both. A certificate is kept only for one of them.
ALTER TABLE tenant.saml_service_providers
    ADD COLUMN require_signed_requests BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN encrypt_assertions BOOLEAN NOT NULL DEFAULT FALSE;
