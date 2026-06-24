DROP INDEX IF EXISTS "user".uq_users_email_global;

CREATE UNIQUE INDEX uq_users_tenant_email
    ON "user".users (tenant_id, LOWER(email))
    WHERE deleted_at IS NULL;
