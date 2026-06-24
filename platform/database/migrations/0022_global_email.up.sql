-- Email becomes globally unique across all tenants.
--
-- Why: sign-in is now `{email, password}` only (no tenant_id input),
-- and the backend looks up the user by email across the platform. Before
-- this change emails were only unique per (tenant_id, email), which would
-- have left sign-in ambiguous when the same email appeared in multiple
-- tenants.
--
-- Multi-tenant membership is now expressed through rbac.user_roles
-- (user → tenant → role) rather than duplicate user rows.
DROP INDEX IF EXISTS "user".uq_users_tenant_email;

CREATE UNIQUE INDEX uq_users_email_global
    ON "user".users (LOWER(email))
    WHERE deleted_at IS NULL;
