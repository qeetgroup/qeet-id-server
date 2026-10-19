-- 0139_user_deleted_by — record who soft-deleted a user.
--
-- Soft delete was a single UPDATE with no actor, so the recycle bin couldn't say
-- who deleted an account and the audit trail showed a restore with no deletion
-- before it. deleted_by is the admin who deleted the user (NULL for deletions
-- before this column, by a system process, or once that admin is purged), and
-- restore clears it.
ALTER TABLE "user".users ADD COLUMN deleted_by UUID REFERENCES "user".users (id) ON DELETE SET NULL;
