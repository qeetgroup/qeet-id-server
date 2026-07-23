-- 0026_optional_tenant — drop NOT NULL on tenant_id: signup is tenant-less, membership lives in rbac.user_roles
ALTER TABLE "user".users  ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE auth.sessions ALTER COLUMN tenant_id DROP NOT NULL;
