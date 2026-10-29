-- Service providers the up migration set to name their persistent NameID stay set.
DROP TABLE IF EXISTS tenant.saml_idp_persistent_ids;
ALTER TABLE tenant.saml_service_providers DROP COLUMN IF EXISTS attributes;
