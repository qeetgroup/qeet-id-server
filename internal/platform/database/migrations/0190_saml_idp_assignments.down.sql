DROP TABLE IF EXISTS tenant.saml_sp_group_assignments;
DROP TABLE IF EXISTS tenant.saml_sp_user_assignments;
ALTER TABLE tenant.saml_service_providers DROP COLUMN IF EXISTS assignment_required;
