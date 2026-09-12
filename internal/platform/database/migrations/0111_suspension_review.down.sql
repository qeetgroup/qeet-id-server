DROP TRIGGER IF EXISTS capture_suspension_transition ON "user".users;
DROP FUNCTION IF EXISTS "user".capture_suspension_transition();
DROP INDEX IF EXISTS "user".users_suspended_tenant;
ALTER TABLE "user".users
    DROP COLUMN suspended_at,
    DROP COLUMN suspension_reason,
    DROP COLUMN suspension_source,
    DROP COLUMN suspension_risk,
    DROP COLUMN suspension_review;
