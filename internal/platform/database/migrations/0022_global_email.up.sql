-- 0022_global_email — make email globally unique (was per-tenant).
-- Why: sign-in is now {email, password} with no tenant_id input, so an email must
-- resolve to one user platform-wide; multi-tenant membership lives in rbac.user_roles, not duplicate user rows.
DROP INDEX IF EXISTS "user".uq_users_tenant_email;

CREATE UNIQUE INDEX uq_users_email_global
    ON "user".users (LOWER(email))
    WHERE deleted_at IS NULL;
