ALTER TABLE tenant.saml_connections
    DROP COLUMN IF EXISTS metadata_error,
    DROP COLUMN IF EXISTS metadata_refreshed_at,
    DROP COLUMN IF EXISTS metadata_checked_at,
    DROP COLUMN IF EXISTS metadata_url;
