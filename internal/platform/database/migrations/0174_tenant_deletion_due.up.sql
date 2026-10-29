-- 0174_tenant_deletion_due — deleting an organisation can be called off.
--
-- Deleting one took effect at once and for good: its members could no longer
-- sign in, so nobody could undo a mistake. A deletion is now scheduled: the
-- organisation keeps working until deletion_due_at, an owner can cancel it
-- until then, and a background job deletes it once due.
ALTER TABLE tenant.tenants ADD COLUMN deletion_due_at TIMESTAMPTZ;
CREATE INDEX tenants_deletion_due ON tenant.tenants (deletion_due_at)
    WHERE deletion_due_at IS NOT NULL AND deleted_at IS NULL;
