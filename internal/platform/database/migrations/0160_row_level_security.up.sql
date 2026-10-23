-- 0160_row_level_security — PostgreSQL row-level security on the
-- organisation-owned tables, beneath the application's own tenant filtering.
--
-- The application's connections run as qeet_app and set qeet.tenant_id to the
-- organisation of the request. Each table below then shows and accepts only
-- that organisation's rows; with no organisation set (background jobs, sign-in,
-- the few requests that act across organisations) every row. Tables holding a
-- person's own data across organisations, and platform-wide ones, have no
-- policy. The owner-guard functions run as their owner, so they always see
-- every organisation.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qeet_app') THEN
        CREATE ROLE qeet_app NOLOGIN;
    END IF;
END
$$;
GRANT qeet_app TO CURRENT_USER;

GRANT USAGE ON SCHEMA audit, auth, platform, public, qeetai, rbac, tenant, "user" TO qeet_app;
GRANT ALL ON ALL TABLES IN SCHEMA audit, auth, platform, public, qeetai, rbac, tenant, "user" TO qeet_app;
GRANT ALL ON ALL SEQUENCES IN SCHEMA audit, auth, platform, public, qeetai, rbac, tenant, "user" TO qeet_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA audit, auth, platform, public, qeetai, rbac, tenant, "user" TO qeet_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit, auth, platform, public, qeetai, rbac, tenant, "user" GRANT ALL ON TABLES TO qeet_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit, auth, platform, public, qeetai, rbac, tenant, "user" GRANT ALL ON SEQUENCES TO qeet_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit, auth, platform, public, qeetai, rbac, tenant, "user" GRANT EXECUTE ON FUNCTIONS TO qeet_app;

-- The organisation a connection is scoped to; NULL for none.
CREATE FUNCTION platform.current_tenant() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT NULLIF(current_setting('qeet.tenant_id', true), '')::uuid $$;

ALTER FUNCTION tenant.refuse_last_owner(uuid, uuid) SECURITY DEFINER SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION tenant.keep_owner_on_role_removal() SECURITY DEFINER SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION tenant.keep_owner_on_account_change() SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

ALTER TABLE audit.actor_baselines ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit.actor_baselines
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE audit.anomalies ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit.anomalies
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE audit.anomaly_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit.anomaly_settings
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.abac_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.abac_policies
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.agents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.agents
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.api_keys
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.bot_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.bot_events
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.bot_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.bot_settings
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.credentials
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.oidc_clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.oidc_clients
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.oidc_resources ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.oidc_resources
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.relation_tuples ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.relation_tuples
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.risk_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.risk_settings
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.security_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.security_events
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE auth.service_principals ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth.service_principals
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE qeetai.conversations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON qeetai.conversations
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE qeetai.messages ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON qeetai.messages
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE qeetai.provider_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON qeetai.provider_settings
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE rbac.group_roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rbac.group_roles
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE rbac.roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rbac.roles
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.admin_portal_links ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.admin_portal_links
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.auth_hooks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.auth_hooks
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.auth_policy ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.auth_policy
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.billing_checkouts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.billing_checkouts
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.billing_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.billing_profiles
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.branding ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.branding
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.compliance_evidence_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.compliance_evidence_runs
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.directory_alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.directory_alerts
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.directory_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.directory_events
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.directory_mappings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.directory_mappings
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.directory_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.directory_profiles
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.domains ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.domains
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.email_templates ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.email_templates
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.group_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.group_members
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.group_templates ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.group_templates
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.groups
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.invites ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.invites
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.invoices ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.invoices
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.ip_rules ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.ip_rules
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.ip_rules_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.ip_rules_config
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.ldap_connections ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.ldap_connections
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.log_sinks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.log_sinks
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.retention_policy ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.retention_policy
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.saml_connections ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.saml_connections
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.saml_service_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.saml_service_providers
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.scim_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.scim_tokens
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.secrets
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.security_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.security_policies
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.social_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.social_providers
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.subscriptions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.subscriptions
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.token_vault_connect_states ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.token_vault_connect_states
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.token_vault_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.token_vault_grants
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.token_vault_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.token_vault_providers
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());

ALTER TABLE tenant.webhook_subscriptions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.webhook_subscriptions
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
