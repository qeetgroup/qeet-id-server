ALTER TABLE tenant.saml_service_providers
    DROP COLUMN IF EXISTS encrypt_assertions,
    DROP COLUMN IF EXISTS require_signed_requests;
