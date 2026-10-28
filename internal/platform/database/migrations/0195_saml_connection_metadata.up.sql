-- 0195_saml_connection_metadata — a SAML connection can take its IdP settings
-- from the IdP's metadata, and one given a metadata URL refreshes from it, so
-- it picks up the IdP's next signing certificate by itself.
--
-- metadata_checked_at is the last attempt to fetch it, metadata_refreshed_at
-- the last time the connection took its settings from metadata, and
-- metadata_error why the last attempt failed (NULL once one succeeds).
ALTER TABLE tenant.saml_connections
    ADD COLUMN metadata_url TEXT,
    ADD COLUMN metadata_checked_at TIMESTAMPTZ,
    ADD COLUMN metadata_refreshed_at TIMESTAMPTZ,
    ADD COLUMN metadata_error TEXT;
