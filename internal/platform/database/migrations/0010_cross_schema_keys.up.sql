-- 0010_cross_schema_keys — the foreign keys from one schema into another.
--
-- They come after every table exists because the schemas reference each other
-- in circles: an account has a home organization and an organization has
-- members, for one.

ALTER TABLE platform.audit_chain_checkpoints ADD CONSTRAINT audit_chain_checkpoints_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE platform.audit_purge_checkpoints ADD CONSTRAINT audit_purge_checkpoints_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE platform.email_messages ADD CONSTRAINT email_messages_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE platform.email_suppressions ADD CONSTRAINT email_suppressions_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE SET NULL;
ALTER TABLE platform.rate_limit_overrides ADD CONSTRAINT rate_limit_overrides_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE platform.sales_leads ADD CONSTRAINT sales_leads_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE SET NULL;

ALTER TABLE account.export_requests ADD CONSTRAINT export_requests_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE account.external_identities ADD CONSTRAINT external_identities_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE account.purge_requests ADD CONSTRAINT purge_requests_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE account.users ADD CONSTRAINT users_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id);

ALTER TABLE organization.admin_portal_links ADD CONSTRAINT admin_portal_links_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES account.users (id) ON DELETE SET NULL;
ALTER TABLE organization.break_glass_members ADD CONSTRAINT break_glass_members_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES account.users (id) ON DELETE SET NULL;
ALTER TABLE organization.break_glass_members ADD CONSTRAINT break_glass_members_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE organization.directory_alerts ADD CONSTRAINT directory_alerts_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE organization.directory_events ADD CONSTRAINT directory_events_resolved_by_fkey
    FOREIGN KEY (resolved_by) REFERENCES account.users (id) ON DELETE SET NULL;
ALTER TABLE organization.directory_profiles ADD CONSTRAINT directory_profiles_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE organization.group_members ADD CONSTRAINT group_members_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE organization.invites ADD CONSTRAINT invites_role_id_fkey
    FOREIGN KEY (organization_id, role_id) REFERENCES rbac.roles (organization_id, id) ON DELETE SET NULL (role_id);
ALTER TABLE organization.saml_idp_persistent_ids ADD CONSTRAINT saml_idp_persistent_ids_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE organization.saml_sp_user_assignments ADD CONSTRAINT saml_sp_user_assignments_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE organization.subscriptions ADD CONSTRAINT subscriptions_plan_id_fkey
    FOREIGN KEY (plan_id) REFERENCES platform.billing_plans (id);
ALTER TABLE organization.token_vault_connect_states ADD CONSTRAINT token_vault_connect_states_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE organization.token_vault_grants ADD CONSTRAINT token_vault_grants_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;

ALTER TABLE rbac.access_requests ADD CONSTRAINT access_requests_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE rbac.group_roles ADD CONSTRAINT group_roles_group_id_fkey
    FOREIGN KEY (organization_id, group_id) REFERENCES organization.groups (organization_id, id) ON DELETE CASCADE;
ALTER TABLE rbac.group_roles ADD CONSTRAINT group_roles_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE rbac.roles ADD CONSTRAINT roles_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE rbac.user_roles ADD CONSTRAINT user_roles_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE rbac.user_roles ADD CONSTRAINT user_roles_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;

ALTER TABLE auth.abac_policies ADD CONSTRAINT abac_policies_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.abac_policy_versions ADD CONSTRAINT abac_policy_versions_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.admin_portal_sessions ADD CONSTRAINT admin_portal_sessions_link_id_fkey
    FOREIGN KEY (link_id) REFERENCES organization.admin_portal_links (id) ON DELETE CASCADE;
ALTER TABLE auth.agents ADD CONSTRAINT agents_sponsor_user_id_fkey
    FOREIGN KEY (sponsor_user_id) REFERENCES account.users (id) ON DELETE SET NULL;
ALTER TABLE auth.agents ADD CONSTRAINT agents_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.api_keys ADD CONSTRAINT api_keys_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.api_keys ADD CONSTRAINT api_keys_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.authz_decisions ADD CONSTRAINT authz_decisions_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.bot_settings ADD CONSTRAINT bot_settings_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.credentials ADD CONSTRAINT credentials_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.credentials ADD CONSTRAINT credentials_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE SET NULL;
ALTER TABLE auth.login_codes ADD CONSTRAINT login_codes_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.login_codes ADD CONSTRAINT login_codes_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.login_context_history ADD CONSTRAINT login_context_history_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.login_context_history ADD CONSTRAINT login_context_history_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.login_sessions ADD CONSTRAINT login_sessions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.magic_links ADD CONSTRAINT magic_links_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_attempt_budgets ADD CONSTRAINT mfa_attempt_budgets_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_failure_streaks ADD CONSTRAINT mfa_failure_streaks_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_login_challenges ADD CONSTRAINT mfa_login_challenges_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_login_challenges ADD CONSTRAINT mfa_login_challenges_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_otp_factors ADD CONSTRAINT mfa_otp_factors_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_push_challenges ADD CONSTRAINT mfa_push_challenges_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_push_devices ADD CONSTRAINT mfa_push_devices_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_push_pairings ADD CONSTRAINT mfa_push_pairings_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE SET NULL;
ALTER TABLE auth.mfa_push_pairings ADD CONSTRAINT mfa_push_pairings_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_recovery_codes ADD CONSTRAINT mfa_recovery_codes_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_totp ADD CONSTRAINT mfa_totp_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.mfa_verifications ADD CONSTRAINT mfa_verifications_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.notifications ADD CONSTRAINT notifications_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.notifications ADD CONSTRAINT notifications_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.oauth_states ADD CONSTRAINT oauth_states_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_authorization_codes ADD CONSTRAINT oidc_authorization_codes_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_ciba_requests ADD CONSTRAINT oidc_ciba_requests_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_ciba_requests ADD CONSTRAINT oidc_ciba_requests_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_clients ADD CONSTRAINT oidc_clients_reviewed_by_fkey
    FOREIGN KEY (reviewed_by) REFERENCES account.users (id) ON DELETE SET NULL;
ALTER TABLE auth.oidc_clients ADD CONSTRAINT oidc_clients_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_consent_requests ADD CONSTRAINT oidc_consent_requests_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_consents ADD CONSTRAINT oidc_consents_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_device_codes ADD CONSTRAINT oidc_device_codes_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_device_codes ADD CONSTRAINT oidc_device_codes_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_logout_deliveries ADD CONSTRAINT oidc_logout_deliveries_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_refresh_tokens ADD CONSTRAINT oidc_refresh_tokens_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_refresh_tokens ADD CONSTRAINT oidc_refresh_tokens_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.oidc_resources ADD CONSTRAINT oidc_resources_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.passkey_credentials ADD CONSTRAINT passkey_credentials_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.password_credentials ADD CONSTRAINT password_credentials_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.password_resets ADD CONSTRAINT password_resets_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.platform_social_identities ADD CONSTRAINT platform_social_identities_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.platform_social_link_codes ADD CONSTRAINT platform_social_link_codes_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.relation_tuples ADD CONSTRAINT relation_tuples_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id);
ALTER TABLE auth.risk_settings ADD CONSTRAINT risk_settings_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.saml_authn_requests ADD CONSTRAINT saml_authn_requests_connection_id_fkey
    FOREIGN KEY (connection_id) REFERENCES organization.saml_connections (id) ON DELETE CASCADE;
ALTER TABLE auth.saml_replay_ids ADD CONSTRAINT saml_replay_ids_connection_id_fkey
    FOREIGN KEY (connection_id) REFERENCES organization.saml_connections (id) ON DELETE CASCADE;
ALTER TABLE auth.saml_test_sign_ins ADD CONSTRAINT saml_test_sign_ins_connection_id_fkey
    FOREIGN KEY (connection_id) REFERENCES organization.saml_connections (id) ON DELETE CASCADE;
ALTER TABLE auth.service_principals ADD CONSTRAINT service_principals_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.sessions ADD CONSTRAINT sessions_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id);
ALTER TABLE auth.sessions ADD CONSTRAINT sessions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.trusted_devices ADD CONSTRAINT trusted_devices_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE auth.trusted_devices ADD CONSTRAINT trusted_devices_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;
ALTER TABLE auth.webauthn_sessions ADD CONSTRAINT webauthn_sessions_pending_invite_id_fkey
    FOREIGN KEY (pending_invite_id) REFERENCES organization.invites (id) ON DELETE CASCADE;
ALTER TABLE auth.webauthn_sessions ADD CONSTRAINT webauthn_sessions_pending_organization_id_fkey
    FOREIGN KEY (pending_organization_id) REFERENCES organization.organizations (id);
ALTER TABLE auth.webauthn_sessions ADD CONSTRAINT webauthn_sessions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES account.users (id) ON DELETE CASCADE;

ALTER TABLE audit.actor_baselines ADD CONSTRAINT actor_baselines_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE audit.anomalies ADD CONSTRAINT anomalies_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE audit.anomaly_settings ADD CONSTRAINT anomaly_settings_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;

ALTER TABLE qeetai.conversations ADD CONSTRAINT conversations_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id);
ALTER TABLE qeetai.provider_settings ADD CONSTRAINT provider_settings_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE qeetai.settings ADD CONSTRAINT settings_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
ALTER TABLE qeetai.usage ADD CONSTRAINT usage_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization.organizations (id) ON DELETE CASCADE;
