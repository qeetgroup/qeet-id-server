-- Signup is tenant-less; membership lives in rbac.user_roles, so both columns may be NULL.
ALTER TABLE "user".users  ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE auth.sessions ALTER COLUMN tenant_id DROP NOT NULL;
