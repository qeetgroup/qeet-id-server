ALTER TABLE "user".email_verifications DROP COLUMN IF EXISTS attempts;
ALTER TABLE "user".phone_verifications DROP COLUMN IF EXISTS attempts;
