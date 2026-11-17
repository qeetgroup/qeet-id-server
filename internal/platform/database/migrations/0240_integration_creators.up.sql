-- 0251_integration_creators — service principals, SCIM tokens, webhooks, auth hooks and OpenID
-- Connect applications record who created them, so offboarding an administrator can list the
-- integrations they set up. Rows from before this migration have no creator.
ALTER TABLE auth.service_principals ADD COLUMN IF NOT EXISTS created_by UUID;
ALTER TABLE tenant.scim_tokens ADD COLUMN IF NOT EXISTS created_by UUID;
ALTER TABLE tenant.webhook_subscriptions ADD COLUMN IF NOT EXISTS created_by UUID;
ALTER TABLE tenant.auth_hooks ADD COLUMN IF NOT EXISTS created_by UUID;
ALTER TABLE auth.oidc_clients ADD COLUMN IF NOT EXISTS created_by UUID;
