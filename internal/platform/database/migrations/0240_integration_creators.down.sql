ALTER TABLE auth.oidc_clients DROP COLUMN IF EXISTS created_by;
ALTER TABLE tenant.auth_hooks DROP COLUMN IF EXISTS created_by;
ALTER TABLE tenant.webhook_subscriptions DROP COLUMN IF EXISTS created_by;
ALTER TABLE tenant.scim_tokens DROP COLUMN IF EXISTS created_by;
ALTER TABLE auth.service_principals DROP COLUMN IF EXISTS created_by;
