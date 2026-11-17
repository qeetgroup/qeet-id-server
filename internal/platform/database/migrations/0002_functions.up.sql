-- 0002_functions — the functions the tables are built on.
--
-- platform.current_tenant is the organisation a connection is scoped to, which
-- the row-security policies (0011) compare each row with. The audit functions
-- are IMMUTABLE so the audit trail's generated search column and its indexes
-- can use them.

CREATE FUNCTION platform.current_tenant() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT NULLIF(current_setting('qeet.tenant_id', true), '')::uuid $$;

CREATE FUNCTION audit.activity_category(action text) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
    SELECT CASE
        WHEN starts_with(action, 'auth.') THEN 'authentication'
        WHEN starts_with(action, 'auth_policy.') THEN 'authentication'
        WHEN starts_with(action, 'passkey.') THEN 'authentication'
        WHEN starts_with(action, 'recovery.') THEN 'authentication'
        WHEN starts_with(action, 'saml.') THEN 'authentication'
        WHEN starts_with(action, 'social.') THEN 'authentication'
        WHEN starts_with(action, 'social_provider.') THEN 'authentication'
        WHEN starts_with(action, 'ldap.') THEN 'authentication'
        WHEN starts_with(action, 'oidc_connection.') THEN 'authentication'
        WHEN starts_with(action, 'oidc.') THEN 'authentication'
        WHEN starts_with(action, 'oauth.') THEN 'authentication'
        WHEN starts_with(action, 'mfa.') THEN 'authentication'
        WHEN starts_with(action, 'session.') THEN 'authentication'
        WHEN starts_with(action, 'admin_portal.') THEN 'authentication'
        WHEN starts_with(action, 'rbac.') THEN 'authorization'
        WHEN starts_with(action, 'abac.') THEN 'authorization'
        WHEN starts_with(action, 'abac_policy.') THEN 'authorization'
        WHEN starts_with(action, 'rebac.') THEN 'authorization'
        WHEN starts_with(action, 'role.') THEN 'authorization'
        WHEN starts_with(action, 'access_request.') THEN 'authorization'
        WHEN starts_with(action, 'policy.') THEN 'authorization'
        WHEN starts_with(action, 'authzen.') THEN 'authorization'
        WHEN starts_with(action, 'threat.') THEN 'security'
        WHEN starts_with(action, 'risk.') THEN 'security'
        WHEN starts_with(action, 'anomaly.') THEN 'security'
        WHEN starts_with(action, 'bot.') THEN 'security'
        WHEN starts_with(action, 'ip_rules.') THEN 'security'
        WHEN starts_with(action, 'rate_limits.') THEN 'security'
        WHEN starts_with(action, 'security_policy.') THEN 'security'
        WHEN starts_with(action, 'audit.') THEN 'security'
        WHEN starts_with(action, 'siem.') THEN 'security'
        WHEN starts_with(action, 'retention.') THEN 'security'
        WHEN starts_with(action, 'compliance.') THEN 'security'
        WHEN starts_with(action, 'gdpr.') THEN 'security'
        WHEN starts_with(action, 'user.') THEN 'directory'
        WHEN starts_with(action, 'group.') THEN 'directory'
        WHEN starts_with(action, 'group_template.') THEN 'directory'
        WHEN starts_with(action, 'tenant.') THEN 'directory'
        WHEN starts_with(action, 'invite.') THEN 'directory'
        WHEN starts_with(action, 'scim.') THEN 'directory'
        WHEN starts_with(action, 'directory.') THEN 'directory'
        WHEN starts_with(action, 'domain.') THEN 'directory'
        WHEN starts_with(action, 'branding.') THEN 'directory'
        WHEN starts_with(action, 'email.') THEN 'directory'
        WHEN starts_with(action, 'email_template.') THEN 'directory'
        WHEN starts_with(action, 'phone.') THEN 'directory'
        WHEN starts_with(action, 'agent.') THEN 'developer'
        WHEN starts_with(action, 'apikey.') THEN 'developer'
        WHEN starts_with(action, 'api_key.') THEN 'developer'
        WHEN starts_with(action, 'service_principal.') THEN 'developer'
        WHEN starts_with(action, 'webhook.') THEN 'developer'
        WHEN starts_with(action, 'credential.') THEN 'developer'
        WHEN starts_with(action, 'secret.') THEN 'developer'
        WHEN starts_with(action, 'vault.') THEN 'developer'
        WHEN starts_with(action, 'auth_hook.') THEN 'developer'
        WHEN starts_with(action, 'vc.') THEN 'developer'
        WHEN starts_with(action, 'qeetai.') THEN 'developer'
        WHEN starts_with(action, 'billing.') THEN 'system'
        WHEN starts_with(action, 'system.') THEN 'system'
        ELSE 'system'
    END
$$;

CREATE FUNCTION audit.activity_severity(action text) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
    SELECT CASE
        WHEN starts_with(action, 'threat.') OR strpos(action, 'reuse') > 0 OR strpos(action, 'breach') > 0 OR strpos(action, 'attack') > 0 OR strpos(action, 'malicious') > 0 THEN 'critical'
        WHEN regexp_split_to_array(action, '[._]') && ARRAY['failed', 'locked', 'blocked', 'throttled', 'denied', 'rejected', 'refused'] THEN 'error'
        WHEN regexp_split_to_array(action, '[._]') && ARRAY['deleted', 'purged', 'revoked', 'rotated', 'disabled', 'suspended', 'canceled', 'reset', 'decommissioned'] THEN 'warning'
        WHEN regexp_split_to_array(action, '[._]') && ARRAY['created', 'updated', 'enabled', 'activated', 'verified', 'accepted', 'confirmed', 'login', 'succeeded', 'refreshed', 'registered', 'enrolled', 'restored'] THEN 'success'
        ELSE 'info'
    END
$$;

CREATE FUNCTION audit.search_query(q text) RETURNS tsquery
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
    SELECT CASE
        WHEN q ~ '"|(^|\s)-|\sOR\s' THEN
            websearch_to_tsquery('simple', regexp_replace(q, '[^[:alnum:]"\s-]+', ' ', 'g'))
        ELSE (
            SELECT to_tsquery('simple', string_agg(quote_literal(w) || ':*', ' & '))
            FROM regexp_split_to_table(lower(q), '[^[:alnum:]]+') AS w
            WHERE w <> ''
        )
    END
$$;

CREATE FUNCTION audit.search_text(action text, resource_type text, actor_type text, user_agent text, ip inet, metadata jsonb) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
    SELECT regexp_replace(lower(
        coalesce(action, '') || ' ' || coalesce(resource_type, '') || ' ' || coalesce(actor_type, '') || ' ' ||
        coalesce(user_agent, '') || ' ' || coalesce(host(ip), '') || ' ' || coalesce(metadata::text, '')
    ), '[^[:alnum:]]+', ' ', 'g')
$$;
