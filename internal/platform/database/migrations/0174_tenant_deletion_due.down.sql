DROP INDEX tenant.tenants_deletion_due;
ALTER TABLE tenant.tenants DROP COLUMN deletion_due_at;
