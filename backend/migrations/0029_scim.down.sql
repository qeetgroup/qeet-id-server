DROP INDEX IF EXISTS "user".idx_users_scim_external;
DROP TABLE IF EXISTS tenant.scim_tokens;
ALTER TABLE "user".users DROP COLUMN IF EXISTS provisioned_via;
ALTER TABLE "user".users DROP COLUMN IF EXISTS external_id;
