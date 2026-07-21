-- Requires every row to have a tenant_id; backfill tenant-less rows first.
ALTER TABLE auth.sessions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE "user".users  ALTER COLUMN tenant_id SET NOT NULL;
