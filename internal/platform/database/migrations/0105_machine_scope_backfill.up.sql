-- 0105_machine_scope_backfill makes each existing machine credential's
-- effective access explicit.
--
-- Before the typed route policy landed, rbac.Enforce gated end-user principals
-- only: API keys, service principals, and agents were passed straight through,
-- so a credential with an empty scope array could reach every authenticated
-- route. Enforcement now requires an exact scope match, which would silently
-- revoke every one of those credentials on deploy.
--
-- This backfill writes down the access those credentials already had rather
-- than granting a wildcard. It is behaviour-preserving, not a privilege grant:
-- the rows below could already do all of this. The point is that the grant is
-- now visible in the credential, editable by the tenant, and no longer implied
-- by a gap in the middleware.
--
-- OPERATORS: this is a compatibility floor, not a recommendation. Review these
-- credentials and narrow them to the scopes each integration actually needs;
-- newly issued credentials must name their scopes up front (rbac.ValidateMachineScopes).

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
    widened INTEGER;
BEGIN
    UPDATE auth.api_keys SET scopes = builtin_scopes
    WHERE scopes = '{}' AND revoked_at IS NULL;
    GET DIAGNOSTICS widened = ROW_COUNT;
    RAISE NOTICE '0105: widened % api_keys to the explicit compatibility scope set', widened;

    UPDATE auth.service_principals SET scopes = builtin_scopes
    WHERE scopes = '{}' AND disabled_at IS NULL;
    GET DIAGNOSTICS widened = ROW_COUNT;
    RAISE NOTICE '0105: widened % service_principals to the explicit compatibility scope set', widened;

    UPDATE auth.agents SET scopes = builtin_scopes
    WHERE scopes = '{}' AND status = 'active';
    GET DIAGNOSTICS widened = ROW_COUNT;
    RAISE NOTICE '0105: widened % agents to the explicit compatibility scope set', widened;
END $$;
