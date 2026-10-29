DROP TABLE IF EXISTS auth.abac_policy_versions;
ALTER TABLE auth.abac_policies DROP COLUMN IF EXISTS updated_by, DROP COLUMN IF EXISTS version;
