-- 0217_compliance_records — an erasure request keeps the email and name of the
-- person it was filed for until they are erased, and the retention policy who
-- last changed it.
ALTER TABLE "user".purge_requests
    ADD COLUMN IF NOT EXISTS subject_email TEXT,
    ADD COLUMN IF NOT EXISTS subject_name TEXT;

UPDATE "user".purge_requests r
SET subject_email = u.email, subject_name = u.display_name
FROM "user".users u
WHERE u.id = r.subject_id AND r.status <> 'completed';

ALTER TABLE tenant.retention_policy ADD COLUMN IF NOT EXISTS updated_by UUID;
