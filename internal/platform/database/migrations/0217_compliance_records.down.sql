ALTER TABLE tenant.retention_policy DROP COLUMN IF EXISTS updated_by;
ALTER TABLE "user".purge_requests
    DROP COLUMN IF EXISTS subject_name,
    DROP COLUMN IF EXISTS subject_email;
