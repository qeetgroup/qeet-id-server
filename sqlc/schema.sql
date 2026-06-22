--
-- PostgreSQL database dump
--

\restrict Dt4fSXhS5YSOnMzlDDxUEywdbDoRHpUE1GUW1WlZhTpUab5e8ej6eoP2tQB9hh7

-- Dumped from database version 16.14
-- Dumped by pg_dump version 16.14

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: audit; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA audit;


--
-- Name: auth; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA auth;


--
-- Name: platform; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA platform;


--
-- Name: rbac; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA rbac;


--
-- Name: tenant; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA tenant;


--
-- Name: user; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA "user";


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: events; Type: TABLE; Schema: audit; Owner: -
--

CREATE TABLE audit.events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    actor_user_id uuid,
    actor_type text DEFAULT 'user'::text NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id uuid,
    ip inet,
    user_agent text,
    request_id text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    prev_hash character(64),
    row_hash character(64),
    CONSTRAINT audit_events_hash_both_or_neither CHECK (((prev_hash IS NULL) = (row_hash IS NULL)))
);


--
-- Name: api_keys; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.api_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid,
    name text NOT NULL,
    prefix text NOT NULL,
    key_hash text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: magic_links; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.magic_links (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    email text NOT NULL,
    token_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: mfa_recovery_codes; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_recovery_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    code_hash text NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: mfa_totp; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_totp (
    user_id uuid NOT NULL,
    secret text NOT NULL,
    confirmed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: oidc_authorization_codes; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oidc_authorization_codes (
    code_hash text NOT NULL,
    client_id text NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL,
    nonce text,
    code_challenge text,
    code_challenge_method text,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: oidc_clients; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oidc_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id text NOT NULL,
    client_secret_hash text,
    type text DEFAULT 'confidential'::text NOT NULL,
    name text NOT NULL,
    redirect_uris text[] DEFAULT '{}'::text[] NOT NULL,
    post_logout_uris text[] DEFAULT '{}'::text[] NOT NULL,
    grant_types text[] DEFAULT '{authorization_code,refresh_token}'::text[] NOT NULL,
    scopes text[] DEFAULT '{openid,profile,email}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oidc_clients_type_check CHECK ((type = ANY (ARRAY['confidential'::text, 'public'::text])))
);


--
-- Name: oidc_consents; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oidc_consents (
    user_id uuid NOT NULL,
    client_id text NOT NULL,
    scopes text[] NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: passkey_challenges; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.passkey_challenges (
    challenge_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    challenge bytea NOT NULL,
    kind text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT passkey_challenges_kind_check CHECK ((kind = ANY (ARRAY['register'::text, 'authenticate'::text])))
);


--
-- Name: passkey_credentials; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.passkey_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    sign_count bigint DEFAULT 0 NOT NULL,
    aaguid uuid,
    transports text[],
    name text,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: password_credentials; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.password_credentials (
    user_id uuid NOT NULL,
    password_hash text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: password_resets; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.password_resets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    token_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: refresh_tokens; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.refresh_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    session_id uuid NOT NULL,
    token_hash text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    replaced_by uuid
);


--
-- Name: service_principals; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.service_principals (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    secret_hash text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    disabled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sessions; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid,
    ip inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone
);


--
-- Name: trusted_devices; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.trusted_devices (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    fingerprint_hash text NOT NULL,
    label text,
    last_seen_ip inet,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: outbox; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.outbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    aggregate_id uuid NOT NULL,
    topic text NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    published_at timestamp with time zone,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    last_attempt_at timestamp with time zone
);


--
-- Name: outbox_dead_letter; Type: TABLE; Schema: platform; Owner: -
--

CREATE TABLE platform.outbox_dead_letter (
    id uuid NOT NULL,
    aggregate_id uuid NOT NULL,
    topic text NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    attempts integer NOT NULL,
    last_error text,
    dead_lettered_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version bigint NOT NULL,
    dirty boolean NOT NULL
);


--
-- Name: permissions; Type: TABLE; Schema: rbac; Owner: -
--

CREATE TABLE rbac.permissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key text NOT NULL,
    description text DEFAULT ''::text NOT NULL
);


--
-- Name: role_permissions; Type: TABLE; Schema: rbac; Owner: -
--

CREATE TABLE rbac.role_permissions (
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL
);


--
-- Name: roles; Type: TABLE; Schema: rbac; Owner: -
--

CREATE TABLE rbac.roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: user_roles; Type: TABLE; Schema: rbac; Owner: -
--

CREATE TABLE rbac.user_roles (
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    role_id uuid NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    granted_by uuid
);


--
-- Name: branding; Type: TABLE; Schema: tenant; Owner: -
--

CREATE TABLE tenant.branding (
    tenant_id uuid NOT NULL,
    logo_url text,
    primary_color text,
    secondary_color text,
    custom_domain text,
    email_from_name text,
    email_from_address text,
    settings jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: group_members; Type: TABLE; Schema: tenant; Owner: -
--

CREATE TABLE tenant.group_members (
    group_id uuid NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: groups; Type: TABLE; Schema: tenant; Owner: -
--

CREATE TABLE tenant.groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    parent_id uuid,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: invites; Type: TABLE; Schema: tenant; Owner: -
--

CREATE TABLE tenant.invites (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    email text NOT NULL,
    role_id uuid,
    invited_by uuid,
    token_hash text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT invites_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'accepted'::text, 'revoked'::text, 'expired'::text])))
);


--
-- Name: security_policies; Type: TABLE; Schema: tenant; Owner: -
--

CREATE TABLE tenant.security_policies (
    tenant_id uuid NOT NULL,
    ip_allowlist cidr[] DEFAULT '{}'::cidr[] NOT NULL,
    ip_denylist cidr[] DEFAULT '{}'::cidr[] NOT NULL,
    password_min_length integer DEFAULT 8 NOT NULL,
    password_complexity text DEFAULT 'standard'::text NOT NULL,
    session_max_age interval DEFAULT '30 days'::interval NOT NULL,
    mfa_enforcement text DEFAULT 'optional'::text NOT NULL,
    settings jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT security_policies_mfa_enforcement_check CHECK ((mfa_enforcement = ANY (ARRAY['optional'::text, 'required'::text, 'admin_only'::text]))),
    CONSTRAINT security_policies_password_complexity_check CHECK ((password_complexity = ANY (ARRAY['relaxed'::text, 'standard'::text, 'strict'::text])))
);


--
-- Name: social_providers; Type: TABLE; Schema: tenant; Owner: -
--

CREATE TABLE tenant.social_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    provider text NOT NULL,
    client_id text NOT NULL,
    client_secret text NOT NULL,
    discovery_url text,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: tenants; Type: TABLE; Schema: tenant; Owner: -
--

CREATE TABLE tenant.tenants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug text NOT NULL,
    name text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    plan text DEFAULT 'free'::text NOT NULL,
    region text DEFAULT 'us-east-1'::text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT tenants_status_check CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text, 'deleted'::text])))
);


--
-- Name: webhook_deliveries; Type: TABLE; Schema: tenant; Owner: -
--

CREATE TABLE tenant.webhook_deliveries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    subscription_id uuid NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    status_code integer,
    response_body text,
    error text,
    attempt integer DEFAULT 0 NOT NULL,
    delivered_at timestamp with time zone,
    next_attempt_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: webhook_subscriptions; Type: TABLE; Schema: tenant; Owner: -
--

CREATE TABLE tenant.webhook_subscriptions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    url text NOT NULL,
    secret text NOT NULL,
    events text[] DEFAULT '{}'::text[] NOT NULL,
    disabled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: email_verifications; Type: TABLE; Schema: user; Owner: -
--

CREATE TABLE "user".email_verifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    email text NOT NULL,
    code_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: external_identities; Type: TABLE; Schema: user; Owner: -
--

CREATE TABLE "user".external_identities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    provider text NOT NULL,
    subject text NOT NULL,
    email text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    linked_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: phone_verifications; Type: TABLE; Schema: user; Owner: -
--

CREATE TABLE "user".phone_verifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    phone text NOT NULL,
    code_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: purge_requests; Type: TABLE; Schema: user; Owner: -
--

CREATE TABLE "user".purge_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    requested_by uuid,
    reason text,
    status text DEFAULT 'pending'::text NOT NULL,
    grace_until timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT purge_requests_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'completed'::text, 'cancelled'::text])))
);


--
-- Name: users; Type: TABLE; Schema: user; Owner: -
--

CREATE TABLE "user".users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    email text NOT NULL,
    email_verified_at timestamp with time zone,
    phone text,
    phone_verified_at timestamp with time zone,
    display_name text,
    status text DEFAULT 'active'::text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    mfa_required boolean DEFAULT false NOT NULL,
    CONSTRAINT users_status_check CHECK ((status = ANY (ARRAY['active'::text, 'invited'::text, 'suspended'::text, 'deleted'::text])))
);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: audit; Owner: -
--

ALTER TABLE ONLY audit.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: magic_links magic_links_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.magic_links
    ADD CONSTRAINT magic_links_pkey PRIMARY KEY (id);


--
-- Name: magic_links magic_links_token_hash_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.magic_links
    ADD CONSTRAINT magic_links_token_hash_key UNIQUE (token_hash);


--
-- Name: mfa_recovery_codes mfa_recovery_codes_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_recovery_codes
    ADD CONSTRAINT mfa_recovery_codes_pkey PRIMARY KEY (id);


--
-- Name: mfa_totp mfa_totp_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_totp
    ADD CONSTRAINT mfa_totp_pkey PRIMARY KEY (user_id);


--
-- Name: oidc_authorization_codes oidc_authorization_codes_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oidc_authorization_codes
    ADD CONSTRAINT oidc_authorization_codes_pkey PRIMARY KEY (code_hash);


--
-- Name: oidc_clients oidc_clients_client_id_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oidc_clients
    ADD CONSTRAINT oidc_clients_client_id_key UNIQUE (client_id);


--
-- Name: oidc_clients oidc_clients_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oidc_clients
    ADD CONSTRAINT oidc_clients_pkey PRIMARY KEY (id);


--
-- Name: oidc_consents oidc_consents_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oidc_consents
    ADD CONSTRAINT oidc_consents_pkey PRIMARY KEY (user_id, client_id);


--
-- Name: passkey_challenges passkey_challenges_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.passkey_challenges
    ADD CONSTRAINT passkey_challenges_pkey PRIMARY KEY (challenge_id);


--
-- Name: passkey_credentials passkey_credentials_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.passkey_credentials
    ADD CONSTRAINT passkey_credentials_pkey PRIMARY KEY (id);


--
-- Name: password_credentials password_credentials_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.password_credentials
    ADD CONSTRAINT password_credentials_pkey PRIMARY KEY (user_id);


--
-- Name: password_resets password_resets_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.password_resets
    ADD CONSTRAINT password_resets_pkey PRIMARY KEY (id);


--
-- Name: password_resets password_resets_token_hash_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.password_resets
    ADD CONSTRAINT password_resets_token_hash_key UNIQUE (token_hash);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_token_hash_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: service_principals service_principals_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.service_principals
    ADD CONSTRAINT service_principals_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: trusted_devices trusted_devices_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.trusted_devices
    ADD CONSTRAINT trusted_devices_pkey PRIMARY KEY (id);


--
-- Name: outbox_dead_letter outbox_dead_letter_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.outbox_dead_letter
    ADD CONSTRAINT outbox_dead_letter_pkey PRIMARY KEY (id);


--
-- Name: outbox outbox_pkey; Type: CONSTRAINT; Schema: platform; Owner: -
--

ALTER TABLE ONLY platform.outbox
    ADD CONSTRAINT outbox_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: permissions permissions_key_key; Type: CONSTRAINT; Schema: rbac; Owner: -
--

ALTER TABLE ONLY rbac.permissions
    ADD CONSTRAINT permissions_key_key UNIQUE (key);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: rbac; Owner: -
--

ALTER TABLE ONLY rbac.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (id);


--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: rbac; Owner: -
--

ALTER TABLE ONLY rbac.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_id);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: rbac; Owner: -
--

ALTER TABLE ONLY rbac.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: rbac; Owner: -
--

ALTER TABLE ONLY rbac.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, tenant_id, role_id);


--
-- Name: branding branding_pkey; Type: CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.branding
    ADD CONSTRAINT branding_pkey PRIMARY KEY (tenant_id);


--
-- Name: group_members group_members_pkey; Type: CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.group_members
    ADD CONSTRAINT group_members_pkey PRIMARY KEY (group_id, user_id);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: invites invites_pkey; Type: CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.invites
    ADD CONSTRAINT invites_pkey PRIMARY KEY (id);


--
-- Name: invites invites_token_hash_key; Type: CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.invites
    ADD CONSTRAINT invites_token_hash_key UNIQUE (token_hash);


--
-- Name: security_policies security_policies_pkey; Type: CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.security_policies
    ADD CONSTRAINT security_policies_pkey PRIMARY KEY (tenant_id);


--
-- Name: social_providers social_providers_pkey; Type: CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.social_providers
    ADD CONSTRAINT social_providers_pkey PRIMARY KEY (id);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);


--
-- Name: webhook_deliveries webhook_deliveries_pkey; Type: CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);


--
-- Name: webhook_subscriptions webhook_subscriptions_pkey; Type: CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.webhook_subscriptions
    ADD CONSTRAINT webhook_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: email_verifications email_verifications_pkey; Type: CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".email_verifications
    ADD CONSTRAINT email_verifications_pkey PRIMARY KEY (id);


--
-- Name: external_identities external_identities_pkey; Type: CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".external_identities
    ADD CONSTRAINT external_identities_pkey PRIMARY KEY (id);


--
-- Name: phone_verifications phone_verifications_pkey; Type: CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".phone_verifications
    ADD CONSTRAINT phone_verifications_pkey PRIMARY KEY (id);


--
-- Name: purge_requests purge_requests_pkey; Type: CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".purge_requests
    ADD CONSTRAINT purge_requests_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: idx_audit_actor; Type: INDEX; Schema: audit; Owner: -
--

CREATE INDEX idx_audit_actor ON audit.events USING btree (actor_user_id, created_at DESC) WHERE (actor_user_id IS NOT NULL);


--
-- Name: idx_audit_chain_tip; Type: INDEX; Schema: audit; Owner: -
--

CREATE INDEX idx_audit_chain_tip ON audit.events USING btree (tenant_id, created_at DESC, id DESC) WHERE (row_hash IS NOT NULL);


--
-- Name: idx_audit_resource; Type: INDEX; Schema: audit; Owner: -
--

CREATE INDEX idx_audit_resource ON audit.events USING btree (resource_type, resource_id, created_at DESC);


--
-- Name: idx_audit_tenant_time; Type: INDEX; Schema: audit; Owner: -
--

CREATE INDEX idx_audit_tenant_time ON audit.events USING btree (tenant_id, created_at DESC);


--
-- Name: idx_api_keys_prefix; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_api_keys_prefix ON auth.api_keys USING btree (prefix) WHERE (revoked_at IS NULL);


--
-- Name: idx_api_keys_tenant; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_api_keys_tenant ON auth.api_keys USING btree (tenant_id);


--
-- Name: idx_magic_email; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_magic_email ON auth.magic_links USING btree (tenant_id, lower(email));


--
-- Name: idx_magic_links_expires; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_magic_links_expires ON auth.magic_links USING btree (expires_at) WHERE (used_at IS NULL);


--
-- Name: idx_mfa_recovery_user; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_mfa_recovery_user ON auth.mfa_recovery_codes USING btree (user_id);


--
-- Name: idx_passkey_user; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_passkey_user ON auth.passkey_credentials USING btree (user_id);


--
-- Name: idx_password_resets_expires; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_password_resets_expires ON auth.password_resets USING btree (expires_at) WHERE (used_at IS NULL);


--
-- Name: idx_password_resets_user; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_password_resets_user ON auth.password_resets USING btree (user_id);


--
-- Name: idx_refresh_session; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_refresh_session ON auth.refresh_tokens USING btree (session_id);


--
-- Name: idx_sessions_active; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_sessions_active ON auth.sessions USING btree (user_id) WHERE (revoked_at IS NULL);


--
-- Name: idx_sessions_tenant_active; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_sessions_tenant_active ON auth.sessions USING btree (tenant_id) WHERE (revoked_at IS NULL);


--
-- Name: idx_sessions_user; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_sessions_user ON auth.sessions USING btree (user_id);


--
-- Name: uq_passkey_credid; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX uq_passkey_credid ON auth.passkey_credentials USING btree (credential_id);


--
-- Name: uq_service_principals_tenant_name; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX uq_service_principals_tenant_name ON auth.service_principals USING btree (tenant_id, lower(name));


--
-- Name: uq_trusted_devices; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX uq_trusted_devices ON auth.trusted_devices USING btree (user_id, fingerprint_hash);


--
-- Name: idx_outbox_dlq_dead_lettered_at; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_outbox_dlq_dead_lettered_at ON platform.outbox_dead_letter USING btree (dead_lettered_at DESC);


--
-- Name: idx_outbox_retry_eligible; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_outbox_retry_eligible ON platform.outbox USING btree (last_attempt_at NULLS FIRST) WHERE (published_at IS NULL);


--
-- Name: idx_outbox_unpublished; Type: INDEX; Schema: platform; Owner: -
--

CREATE INDEX idx_outbox_unpublished ON platform.outbox USING btree (created_at) WHERE (published_at IS NULL);


--
-- Name: idx_user_roles_user_tenant; Type: INDEX; Schema: rbac; Owner: -
--

CREATE INDEX idx_user_roles_user_tenant ON rbac.user_roles USING btree (user_id, tenant_id);


--
-- Name: uq_roles_tenant_name; Type: INDEX; Schema: rbac; Owner: -
--

CREATE UNIQUE INDEX uq_roles_tenant_name ON rbac.roles USING btree (tenant_id, lower(name));


--
-- Name: idx_groups_parent; Type: INDEX; Schema: tenant; Owner: -
--

CREATE INDEX idx_groups_parent ON tenant.groups USING btree (parent_id);


--
-- Name: idx_groups_tenant; Type: INDEX; Schema: tenant; Owner: -
--

CREATE INDEX idx_groups_tenant ON tenant.groups USING btree (tenant_id);


--
-- Name: idx_invites_email; Type: INDEX; Schema: tenant; Owner: -
--

CREATE INDEX idx_invites_email ON tenant.invites USING btree (tenant_id, lower(email));


--
-- Name: idx_invites_tenant; Type: INDEX; Schema: tenant; Owner: -
--

CREATE INDEX idx_invites_tenant ON tenant.invites USING btree (tenant_id, status);


--
-- Name: idx_tenants_status; Type: INDEX; Schema: tenant; Owner: -
--

CREATE INDEX idx_tenants_status ON tenant.tenants USING btree (status) WHERE (deleted_at IS NULL);


--
-- Name: idx_webhook_deliv_pending; Type: INDEX; Schema: tenant; Owner: -
--

CREATE INDEX idx_webhook_deliv_pending ON tenant.webhook_deliveries USING btree (next_attempt_at) WHERE (delivered_at IS NULL);


--
-- Name: idx_webhook_deliveries_sub_pending; Type: INDEX; Schema: tenant; Owner: -
--

CREATE INDEX idx_webhook_deliveries_sub_pending ON tenant.webhook_deliveries USING btree (subscription_id, next_attempt_at) WHERE (delivered_at IS NULL);


--
-- Name: idx_webhook_tenant; Type: INDEX; Schema: tenant; Owner: -
--

CREATE INDEX idx_webhook_tenant ON tenant.webhook_subscriptions USING btree (tenant_id);


--
-- Name: uq_social_tenant_provider; Type: INDEX; Schema: tenant; Owner: -
--

CREATE UNIQUE INDEX uq_social_tenant_provider ON tenant.social_providers USING btree (tenant_id, provider);


--
-- Name: uq_tenants_slug; Type: INDEX; Schema: tenant; Owner: -
--

CREATE UNIQUE INDEX uq_tenants_slug ON tenant.tenants USING btree (lower(slug));


--
-- Name: idx_email_verif_user; Type: INDEX; Schema: user; Owner: -
--

CREATE INDEX idx_email_verif_user ON "user".email_verifications USING btree (user_id, created_at DESC);


--
-- Name: idx_phone_verif_user; Type: INDEX; Schema: user; Owner: -
--

CREATE INDEX idx_phone_verif_user ON "user".phone_verifications USING btree (user_id, created_at DESC);


--
-- Name: idx_purge_pending; Type: INDEX; Schema: user; Owner: -
--

CREATE INDEX idx_purge_pending ON "user".purge_requests USING btree (grace_until) WHERE (status = 'pending'::text);


--
-- Name: idx_users_tenant_status; Type: INDEX; Schema: user; Owner: -
--

CREATE INDEX idx_users_tenant_status ON "user".users USING btree (tenant_id, status) WHERE (deleted_at IS NULL);


--
-- Name: uq_ext_identity_provider; Type: INDEX; Schema: user; Owner: -
--

CREATE UNIQUE INDEX uq_ext_identity_provider ON "user".external_identities USING btree (tenant_id, provider, subject);


--
-- Name: uq_users_email_global; Type: INDEX; Schema: user; Owner: -
--

CREATE UNIQUE INDEX uq_users_email_global ON "user".users USING btree (lower(email)) WHERE (deleted_at IS NULL);


--
-- Name: api_keys api_keys_tenant_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.api_keys
    ADD CONSTRAINT api_keys_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: api_keys api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE SET NULL;


--
-- Name: magic_links magic_links_tenant_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.magic_links
    ADD CONSTRAINT magic_links_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: mfa_recovery_codes mfa_recovery_codes_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_recovery_codes
    ADD CONSTRAINT mfa_recovery_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: mfa_totp mfa_totp_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_totp
    ADD CONSTRAINT mfa_totp_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: oidc_clients oidc_clients_tenant_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oidc_clients
    ADD CONSTRAINT oidc_clients_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: oidc_consents oidc_consents_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oidc_consents
    ADD CONSTRAINT oidc_consents_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: passkey_challenges passkey_challenges_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.passkey_challenges
    ADD CONSTRAINT passkey_challenges_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: passkey_credentials passkey_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.passkey_credentials
    ADD CONSTRAINT passkey_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: password_credentials password_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.password_credentials
    ADD CONSTRAINT password_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: password_resets password_resets_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.password_resets
    ADD CONSTRAINT password_resets_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens refresh_tokens_replaced_by_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_replaced_by_fkey FOREIGN KEY (replaced_by) REFERENCES auth.refresh_tokens(id);


--
-- Name: refresh_tokens refresh_tokens_session_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_session_id_fkey FOREIGN KEY (session_id) REFERENCES auth.sessions(id) ON DELETE CASCADE;


--
-- Name: service_principals service_principals_tenant_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.service_principals
    ADD CONSTRAINT service_principals_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id);


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: trusted_devices trusted_devices_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.trusted_devices
    ADD CONSTRAINT trusted_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: role_permissions role_permissions_permission_id_fkey; Type: FK CONSTRAINT; Schema: rbac; Owner: -
--

ALTER TABLE ONLY rbac.role_permissions
    ADD CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES rbac.permissions(id) ON DELETE CASCADE;


--
-- Name: role_permissions role_permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: rbac; Owner: -
--

ALTER TABLE ONLY rbac.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES rbac.roles(id) ON DELETE CASCADE;


--
-- Name: roles roles_tenant_id_fkey; Type: FK CONSTRAINT; Schema: rbac; Owner: -
--

ALTER TABLE ONLY rbac.roles
    ADD CONSTRAINT roles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: user_roles user_roles_role_id_fkey; Type: FK CONSTRAINT; Schema: rbac; Owner: -
--

ALTER TABLE ONLY rbac.user_roles
    ADD CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES rbac.roles(id) ON DELETE CASCADE;


--
-- Name: user_roles user_roles_tenant_id_fkey; Type: FK CONSTRAINT; Schema: rbac; Owner: -
--

ALTER TABLE ONLY rbac.user_roles
    ADD CONSTRAINT user_roles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: branding branding_tenant_id_fkey; Type: FK CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.branding
    ADD CONSTRAINT branding_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: group_members group_members_group_id_fkey; Type: FK CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.group_members
    ADD CONSTRAINT group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES tenant.groups(id) ON DELETE CASCADE;


--
-- Name: group_members group_members_tenant_id_fkey; Type: FK CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.group_members
    ADD CONSTRAINT group_members_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: groups groups_parent_id_fkey; Type: FK CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.groups
    ADD CONSTRAINT groups_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES tenant.groups(id) ON DELETE CASCADE;


--
-- Name: groups groups_tenant_id_fkey; Type: FK CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.groups
    ADD CONSTRAINT groups_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: invites invites_role_id_fkey; Type: FK CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.invites
    ADD CONSTRAINT invites_role_id_fkey FOREIGN KEY (role_id) REFERENCES rbac.roles(id) ON DELETE SET NULL;


--
-- Name: invites invites_tenant_id_fkey; Type: FK CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.invites
    ADD CONSTRAINT invites_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: security_policies security_policies_tenant_id_fkey; Type: FK CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.security_policies
    ADD CONSTRAINT security_policies_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: social_providers social_providers_tenant_id_fkey; Type: FK CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.social_providers
    ADD CONSTRAINT social_providers_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: webhook_deliveries webhook_deliveries_subscription_id_fkey; Type: FK CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_subscription_id_fkey FOREIGN KEY (subscription_id) REFERENCES tenant.webhook_subscriptions(id) ON DELETE CASCADE;


--
-- Name: webhook_subscriptions webhook_subscriptions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: tenant; Owner: -
--

ALTER TABLE ONLY tenant.webhook_subscriptions
    ADD CONSTRAINT webhook_subscriptions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: email_verifications email_verifications_user_id_fkey; Type: FK CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".email_verifications
    ADD CONSTRAINT email_verifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: external_identities external_identities_tenant_id_fkey; Type: FK CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".external_identities
    ADD CONSTRAINT external_identities_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: external_identities external_identities_user_id_fkey; Type: FK CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".external_identities
    ADD CONSTRAINT external_identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: phone_verifications phone_verifications_user_id_fkey; Type: FK CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".phone_verifications
    ADD CONSTRAINT phone_verifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: purge_requests purge_requests_tenant_id_fkey; Type: FK CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".purge_requests
    ADD CONSTRAINT purge_requests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id) ON DELETE CASCADE;


--
-- Name: purge_requests purge_requests_user_id_fkey; Type: FK CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".purge_requests
    ADD CONSTRAINT purge_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;


--
-- Name: users users_tenant_id_fkey; Type: FK CONSTRAINT; Schema: user; Owner: -
--

ALTER TABLE ONLY "user".users
    ADD CONSTRAINT users_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenant.tenants(id);


--
-- PostgreSQL database dump complete
--

\unrestrict Dt4fSXhS5YSOnMzlDDxUEywdbDoRHpUE1GUW1WlZhTpUab5e8ej6eoP2tQB9hh7

