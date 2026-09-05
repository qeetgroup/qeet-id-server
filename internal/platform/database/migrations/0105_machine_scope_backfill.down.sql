-- Reverting restores the empty scope arrays 0105 widened. That is only correct
-- alongside reverting the typed route policy: under the current rbac.Enforce an
-- empty scope set denies every route, whereas before it allowed every route.
-- Credentials scoped by hand after 0105 are indistinguishable from the backfill
-- and are deliberately left alone.

DO $$
DECLARE
    builtin_scopes TEXT[] := ARRAY[
        'tenant.read', 'tenant.write',
        'user.read', 'user.write',
        'role.read', 'role.write',
        'audit.read', 'audit.write',
        'group.read', 'group.write',
        'connection.read', 'connection.write',
        'apikey.read', 'apikey.write',
        'secret.read', 'secret.write',
        'webhook.read', 'webhook.write',
        'billing.read', 'billing.write',
        'branding.write',
        'policy.read', 'policy.write',
        'gdpr.write',
        'analytics.read'
    ];
BEGIN
    UPDATE auth.api_keys SET scopes = '{}' WHERE scopes = builtin_scopes;
    UPDATE auth.service_principals SET scopes = '{}' WHERE scopes = builtin_scopes;
    UPDATE auth.agents SET scopes = '{}' WHERE scopes = builtin_scopes;
END $$;
