-- 0011_row_security — row-level security on the organization-owned tables,
-- beneath the application's own organization filtering.
--
-- The application's connections run as qeet_app and set qeet.organization_id to the
-- organization of the request. Each table below then shows and accepts only
-- that organization's rows; with no organization set (background jobs, sign-in,
-- the few requests that act across organizations) every row. Tables holding a
-- person's own data across organizations, and platform-wide ones, have no
-- policy.

ALTER TABLE platform.audit_chain_checkpoints ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON platform.audit_chain_checkpoints
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE platform.audit_purge_checkpoints ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON platform.audit_purge_checkpoints
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.admin_portal_links ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.admin_portal_links
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.auth_hooks ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.auth_hooks
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.auth_policy ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.auth_policy
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.billing_checkouts ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.billing_checkouts
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.billing_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.billing_profiles
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.branding ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.branding
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.break_glass_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.break_glass_members
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.compliance_audits ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.compliance_audits
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.compliance_control_owners ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.compliance_control_owners
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.compliance_evidence_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.compliance_evidence_runs
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.directory_alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.directory_alerts
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.directory_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.directory_events
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.directory_mappings ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.directory_mappings
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.directory_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.directory_profiles
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.domains ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.domains
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.email_templates ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.email_templates
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.group_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.group_members
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.group_templates ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.group_templates
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.groups
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.invites ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.invites
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.invoices ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.invoices
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.ip_rules ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.ip_rules
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.ip_rules_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.ip_rules_config
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.ldap_connections ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.ldap_connections
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.log_sinks ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.log_sinks
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.login_domain_checks ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.login_domain_checks
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.monthly_active_users ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.monthly_active_users
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.oidc_connections ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.oidc_connections
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.retention_policy ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.retention_policy
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.saml_connection_certificates ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.saml_connection_certificates
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.saml_connection_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.saml_connection_keys
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.saml_connections ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.saml_connections
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.saml_idp_persistent_ids ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.saml_idp_persistent_ids
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.saml_service_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.saml_service_providers
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.saml_sp_group_assignments ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.saml_sp_group_assignments
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.saml_sp_user_assignments ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.saml_sp_user_assignments
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.scim_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.scim_tokens
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.secrets
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.security_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.security_policies
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.social_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.social_providers
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.sso_group_mappings ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.sso_group_mappings
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.subscriptions ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.subscriptions
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.token_vault_connect_states ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.token_vault_connect_states
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.token_vault_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.token_vault_grants
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.token_vault_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.token_vault_providers
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.webhook_delivery_attempts ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.webhook_delivery_attempts
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE organization.webhook_subscriptions ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organization.webhook_subscriptions
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE rbac.access_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON rbac.access_requests
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE rbac.group_roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON rbac.group_roles
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE rbac.roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON rbac.roles
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.abac_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.abac_policies
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.abac_policy_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.abac_policy_versions
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.agents ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.agents
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.api_keys
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.authz_decisions ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.authz_decisions
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.bot_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.bot_events
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.bot_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.bot_settings
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.credentials
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.oidc_clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.oidc_clients
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.oidc_resources ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.oidc_resources
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.relation_tuples ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.relation_tuples
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.risk_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.risk_settings
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.security_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.security_events
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE auth.service_principals ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON auth.service_principals
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE audit.actor_baselines ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON audit.actor_baselines
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE audit.anomalies ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON audit.anomalies
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE audit.anomaly_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON audit.anomaly_settings
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE qeetai.conversation_turns ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON qeetai.conversation_turns
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE qeetai.conversations ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON qeetai.conversations
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE qeetai.messages ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON qeetai.messages
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE qeetai.provider_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON qeetai.provider_settings
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE qeetai.settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON qeetai.settings
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());

ALTER TABLE qeetai.usage ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON qeetai.usage
    USING (platform.current_organization() IS NULL OR organization_id = platform.current_organization())
    WITH CHECK (platform.current_organization() IS NULL OR organization_id = platform.current_organization());
