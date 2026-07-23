-- Reverse 0026: re-require tenant_id on users/sessions (backfill tenant-less rows first).
ALTER TABLE auth.sessions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE "user".users  ALTER COLUMN tenant_id SET NOT NULL;
