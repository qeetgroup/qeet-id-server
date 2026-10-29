DROP TABLE IF EXISTS tenant.sso_group_mappings;
ALTER TABLE tenant.group_members DROP COLUMN IF EXISTS source_connection_id;
ALTER TABLE tenant.saml_connections DROP COLUMN IF EXISTS groups_attribute;
