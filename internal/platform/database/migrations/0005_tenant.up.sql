-- 0005_tenant — organisations and what each one configures: connections,
-- groups, policies, secrets, billing.
--
-- Each table is headed by the package that owns it. A column marked (0010) is a
-- foreign key into another schema, which 0010_cross_schema_keys adds.

-- internal/identity/tenant
CREATE TABLE tenant.tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    plan            TEXT NOT NULL DEFAULT 'free',
    region          TEXT NOT NULL DEFAULT 'us-east-1',
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,
    logo_url        TEXT NOT NULL DEFAULT '',
    deletion_due_at TIMESTAMPTZ,
    CONSTRAINT tenants_plan_check CHECK (plan IN ('free', 'starter', 'pro', 'enterprise')),
    CONSTRAINT tenants_status_check CHECK (status IN ('active', 'suspended', 'deleted'))
);
CREATE INDEX idx_tenants_status ON tenant.tenants (status) WHERE deleted_at IS NULL;
CREATE INDEX tenants_deletion_due ON tenant.tenants (deletion_due_at)
    WHERE deletion_due_at IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX uq_tenants_slug ON tenant.tenants (lower(slug));

-- internal/federation/adminportal
CREATE TABLE tenant.admin_portal_links (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    capabilities TEXT[] NOT NULL,
    created_by   UUID, -- account.users (0010)
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    redeemed_at  TIMESTAMPTZ
);
CREATE INDEX idx_admin_portal_links_tenant ON tenant.admin_portal_links (tenant_id);

-- internal/developer/auth-hooks
CREATE TABLE tenant.auth_hooks (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                  UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    trigger                    TEXT NOT NULL DEFAULT 'post_login',
    url                        TEXT NOT NULL,
    enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
    fail_open                  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    secret_ct                  BYTEA NOT NULL,
    secret_nonce               BYTEA NOT NULL,
    encryption_version         SMALLINT NOT NULL DEFAULT 1,
    last_called_at             TIMESTAMPTZ,
    last_outcome               TEXT,
    last_status_code           INTEGER,
    call_count                 BIGINT NOT NULL DEFAULT 0,
    skip_count                 BIGINT NOT NULL DEFAULT 0,
    deny_count                 BIGINT NOT NULL DEFAULT 0,
    previous_secret_ct         BYTEA,
    previous_secret_nonce      BYTEA,
    previous_secret_expires_at TIMESTAMPTZ,
    created_by                 UUID,
    CONSTRAINT auth_hook_secret_storage_valid CHECK (encryption_version = 1),
    CONSTRAINT auth_hooks_trigger_check CHECK (trigger IN ('post_login')),
    CONSTRAINT auth_hooks_last_outcome_check CHECK (last_outcome IN ('allowed', 'denied', 'skipped'))
);
CREATE INDEX idx_auth_hooks_tenant ON tenant.auth_hooks (tenant_id);

-- internal/access/authorization/authpolicy
CREATE TABLE tenant.auth_policy (
    tenant_id                  UUID PRIMARY KEY REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    password_enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    password_min_length        INTEGER NOT NULL DEFAULT 8,
    password_require_uppercase BOOLEAN NOT NULL DEFAULT FALSE,
    password_require_number    BOOLEAN NOT NULL DEFAULT FALSE,
    password_require_symbol    BOOLEAN NOT NULL DEFAULT FALSE,
    magic_link_enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    passkey_enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    otp_email_enabled          BOOLEAN NOT NULL DEFAULT FALSE,
    otp_sms_enabled            BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    magic_link_ttl_minutes     INTEGER NOT NULL DEFAULT 60,
    self_registration_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    remember_device_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
    lockout_threshold          INTEGER,
    lockout_window_minutes     INTEGER,
    lockout_duration_minutes   INTEGER,
    remember_device_days       INTEGER NOT NULL DEFAULT 30,
    CONSTRAINT auth_policy_lockout_duration_minutes_check CHECK (lockout_duration_minutes > 0),
    CONSTRAINT auth_policy_lockout_threshold_check CHECK (lockout_threshold > 0),
    CONSTRAINT auth_policy_lockout_window_minutes_check CHECK (lockout_window_minutes > 0),
    CONSTRAINT auth_policy_magic_link_ttl_minutes_check CHECK (
        magic_link_ttl_minutes >= 5
        AND magic_link_ttl_minutes <= 1440),
    CONSTRAINT auth_policy_password_min_length_check CHECK (
        password_min_length >= 8
        AND password_min_length <= 128),
    CONSTRAINT auth_policy_remember_device_days_check CHECK (
        remember_device_days >= 1
        AND remember_device_days <= 90)
);

-- internal/operations/billing
CREATE TABLE tenant.billing_profiles (
    tenant_id     UUID PRIMARY KEY REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    legal_name    TEXT NOT NULL DEFAULT '',
    billing_email TEXT NOT NULL DEFAULT '',
    address_line1 TEXT NOT NULL DEFAULT '',
    address_line2 TEXT NOT NULL DEFAULT '',
    city          TEXT NOT NULL DEFAULT '',
    state         TEXT NOT NULL DEFAULT '',
    postal_code   TEXT NOT NULL DEFAULT '',
    country       TEXT NOT NULL DEFAULT '',
    tax_id_type   TEXT NOT NULL DEFAULT 'none',
    tax_id        TEXT NOT NULL DEFAULT '',
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT billing_profiles_tax_id_type_check CHECK (tax_id_type IN ('none', 'gstin', 'vat'))
);

-- internal/identity/tenant/branding
CREATE TABLE tenant.branding (
    tenant_id          UUID PRIMARY KEY REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    logo_url           TEXT,
    primary_color      TEXT,
    secondary_color    TEXT,
    custom_domain      TEXT,
    email_from_name    TEXT,
    email_from_address TEXT,
    settings           JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- internal/identity/domainverify
CREATE TABLE tenant.break_glass_members (
    tenant_id  UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    user_id    UUID NOT NULL, -- account.users (0010)
    created_by UUID, -- account.users (0010)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX idx_break_glass_members_user ON tenant.break_glass_members (user_id);

-- internal/operations/gdpr
CREATE TABLE tenant.compliance_audits (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    framework  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    body       TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT '',
    reference  TEXT NOT NULL DEFAULT '',
    issued_on  DATE NOT NULL,
    expires_on DATE,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT compliance_audits_body_check CHECK (char_length(body) >= 1 AND char_length(body) <= 200),
    CONSTRAINT compliance_audits_check CHECK (expires_on IS NULL OR expires_on >= issued_on),
    CONSTRAINT compliance_audits_framework_check CHECK (framework IN ('soc2', 'iso27001')),
    CONSTRAINT compliance_audits_kind_check CHECK (kind IN ('audit', 'certificate')),
    CONSTRAINT compliance_audits_reference_check CHECK (char_length(reference) <= 200),
    CONSTRAINT compliance_audits_scope_check CHECK (char_length(scope) <= 2000)
);
CREATE INDEX idx_compliance_audits_tenant ON tenant.compliance_audits (tenant_id, issued_on DESC);

-- internal/operations/gdpr
CREATE TABLE tenant.compliance_control_owners (
    tenant_id  UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    user_id    UUID NOT NULL,
    updated_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, control_id),
    CONSTRAINT compliance_control_owners_control_id_check CHECK (
        char_length(control_id) >= 1
        AND char_length(control_id) <= 64)
);

-- internal/operations/gdpr
CREATE TABLE tenant.compliance_evidence_runs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    framework    TEXT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_by UUID,
    pass_count   INTEGER NOT NULL DEFAULT 0,
    fail_count   INTEGER NOT NULL DEFAULT 0,
    na_count     INTEGER NOT NULL DEFAULT 0,
    controls     JSONB NOT NULL DEFAULT '[]'::jsonb,
    CONSTRAINT compliance_evidence_runs_framework_check CHECK (framework IN ('soc2', 'iso27001'))
);
CREATE INDEX idx_compliance_evidence_runs_lookup
    ON tenant.compliance_evidence_runs (tenant_id, framework, generated_at DESC);

-- internal/federation/directory
CREATE TABLE tenant.directory_alerts (
    id               UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    user_id          UUID NOT NULL, -- account.users (0010)
    name             TEXT NOT NULL,
    connection_id    TEXT,
    threshold        INTEGER NOT NULL DEFAULT 1,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_notified_at TIMESTAMPTZ,
    CONSTRAINT directory_alerts_name_check CHECK (char_length(name) >= 1 AND char_length(name) <= 100),
    CONSTRAINT directory_alerts_threshold_check CHECK (threshold >= 1 AND threshold <= 100)
);
CREATE INDEX directory_alerts_tenant ON tenant.directory_alerts (tenant_id, user_id);

-- internal/federation/directory
CREATE TABLE tenant.directory_events (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    connection_id TEXT NOT NULL,
    operation     TEXT NOT NULL,
    trigger_type  TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL DEFAULT '',
    started_at    TIMESTAMPTZ NOT NULL,
    duration_ms   BIGINT NOT NULL,
    http_status   INTEGER NOT NULL,
    status        TEXT NOT NULL,
    users_synced  INTEGER NOT NULL DEFAULT 0,
    groups_synced INTEGER NOT NULL DEFAULT 0,
    error_code    TEXT NOT NULL DEFAULT '',
    message       TEXT NOT NULL DEFAULT '',
    category      TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT '',
    resolution    TEXT NOT NULL DEFAULT 'open',
    resolved_at   TIMESTAMPTZ,
    resolved_by   UUID, -- account.users (0010)
    retry_of      UUID,
    reason        TEXT NOT NULL DEFAULT '',
    params        JSONB NOT NULL DEFAULT '{}'::jsonb,
    subject       TEXT NOT NULL DEFAULT '',
    user_id       UUID,
    UNIQUE (tenant_id, id),
    CONSTRAINT directory_events_retry_of_fkey FOREIGN KEY (tenant_id, retry_of)
        REFERENCES tenant.directory_events (tenant_id, id) ON DELETE SET NULL (retry_of),
    CONSTRAINT directory_events_duration_ms_check CHECK (duration_ms >= 0),
    CONSTRAINT directory_events_groups_synced_check CHECK (groups_synced >= 0),
    CONSTRAINT directory_events_http_status_check CHECK (http_status >= 100 AND http_status <= 599),
    CONSTRAINT directory_events_resolution_check CHECK (resolution IN ('open', 'resolved', 'retried')),
    CONSTRAINT directory_events_resource_type_check CHECK (resource_type IN ('user', 'group', 'connection')),
    CONSTRAINT directory_events_severity_check CHECK (severity IN ('', 'warning', 'critical')),
    CONSTRAINT directory_events_status_check CHECK (status IN ('success', 'warning', 'failed')),
    CONSTRAINT directory_events_trigger_type_check CHECK (trigger_type IN ('push', 'manual', 'sign-in')),
    CONSTRAINT directory_events_users_synced_check CHECK (users_synced >= 0)
);
CREATE INDEX directory_events_connection_started
    ON tenant.directory_events (tenant_id, connection_id, started_at DESC);
CREATE INDEX directory_events_open_errors ON tenant.directory_events (tenant_id, started_at DESC)
    WHERE status <> 'success' AND resolution = 'open';
CREATE INDEX directory_events_tenant_started ON tenant.directory_events (tenant_id, started_at DESC, id DESC);

-- internal/federation/directory
CREATE TABLE tenant.directory_mappings (
    id               UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    connection_id    TEXT NOT NULL,
    source_attribute TEXT NOT NULL,
    target_field     TEXT NOT NULL,
    value_type       TEXT NOT NULL,
    transform        TEXT NOT NULL,
    pattern          TEXT NOT NULL DEFAULT '',
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    required         BOOLEAN NOT NULL DEFAULT FALSE,
    version          INTEGER NOT NULL DEFAULT 1,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT directory_mappings_pattern_check CHECK (char_length(pattern) <= 256),
    CONSTRAINT directory_mappings_source_attribute_check CHECK (
        char_length(source_attribute) >= 1
        AND char_length(source_attribute) <= 128),
    CONSTRAINT directory_mappings_target_field_check CHECK (target_field IN (
            'email', 'display_name', 'first_name', 'last_name', 'department', 'title', 'manager_id', 'groups')),
    CONSTRAINT directory_mappings_transform_check CHECK (transform IN (
            'none', 'trim', 'lowercase', 'uppercase', 'extract')),
    CONSTRAINT directory_mappings_value_type_check CHECK (value_type IN ('string', 'array'))
);
CREATE UNIQUE INDEX directory_mappings_active_target ON tenant.directory_mappings (tenant_id, connection_id, target_field)
    WHERE enabled;
CREATE INDEX directory_mappings_connection
    ON tenant.directory_mappings (tenant_id, connection_id, created_at, id);

-- internal/federation/directory
CREATE TABLE tenant.directory_profiles (
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    user_id       UUID NOT NULL, -- account.users (0010)
    connection_id TEXT NOT NULL,
    profile       JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id, connection_id)
);

-- internal/identity/domainverify
CREATE TABLE tenant.domains (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    domain             TEXT NOT NULL,
    verification_token TEXT NOT NULL,
    verified_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_checked_at    TIMESTAMPTZ,
    last_error         TEXT,
    sso_enabled        BOOLEAN NOT NULL DEFAULT FALSE,
    jit_enabled        BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX uq_tenant_domain ON tenant.domains (tenant_id, lower(domain));
CREATE UNIQUE INDEX uq_verified_domain ON tenant.domains (lower(domain)) WHERE verified_at IS NOT NULL;

-- internal/operations/email
CREATE TABLE tenant.email_templates (
    tenant_id    UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    template_key TEXT NOT NULL,
    subject      TEXT NOT NULL,
    body         TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    options      JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, template_key)
);

-- internal/identity/groups
CREATE TABLE tenant.group_templates (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    nodes       JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_group_templates_tenant ON tenant.group_templates (tenant_id, created_at DESC);
CREATE UNIQUE INDEX uq_group_templates_tenant_name ON tenant.group_templates (tenant_id, lower(name));

-- internal/identity/groups
CREATE TABLE tenant.groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    parent_id       UUID,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    external_id     TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    provisioned_via TEXT,
    UNIQUE (tenant_id, id),
    CONSTRAINT groups_tenant_parent_fkey FOREIGN KEY (tenant_id, parent_id)
        REFERENCES tenant.groups (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT groups_provisioned_via_check CHECK (provisioned_via = 'scim')
);
CREATE INDEX idx_groups_parent ON tenant.groups (parent_id);
CREATE UNIQUE INDEX uq_groups_tenant_external ON tenant.groups (tenant_id, external_id)
    WHERE external_id IS NOT NULL;
CREATE UNIQUE INDEX uq_groups_tenant_name ON tenant.groups (tenant_id, lower(btrim(name)))
    WHERE external_id IS NULL;

-- internal/identity/groups
CREATE TABLE tenant.group_members (
    group_id             UUID NOT NULL,
    user_id              UUID NOT NULL, -- account.users (0010)
    tenant_id            UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    added_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_connection_id UUID,
    PRIMARY KEY (group_id, user_id),
    CONSTRAINT group_members_group_id_fkey FOREIGN KEY (tenant_id, group_id)
        REFERENCES tenant.groups (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX group_members_source ON tenant.group_members (source_connection_id, user_id)
    WHERE source_connection_id IS NOT NULL;
CREATE INDEX group_members_tenant_id_idx ON tenant.group_members (tenant_id);

-- internal/identity/invitations
CREATE TABLE tenant.invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE, -- rbac.roles (0010)
    email       TEXT NOT NULL,
    role_id     UUID, -- rbac.roles (0010)
    invited_by  UUID,
    token_hash  TEXT NOT NULL UNIQUE,
    status      TEXT NOT NULL DEFAULT 'pending',
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT invites_status_check CHECK (status IN (
            'pending', 'accepted', 'revoked', 'expired', 'declined'))
);
CREATE INDEX idx_invites_email ON tenant.invites (tenant_id, lower(email));
CREATE INDEX idx_invites_tenant ON tenant.invites (tenant_id, status);

-- internal/operations/billing
CREATE TABLE tenant.invoices (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    plan_code            TEXT NOT NULL,
    currency             TEXT NOT NULL,
    amount_minor         BIGINT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'paid',
    period_start         TIMESTAMPTZ NOT NULL,
    period_end           TIMESTAMPTZ NOT NULL,
    issued_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    taxable_amount_minor BIGINT NOT NULL DEFAULT 0,
    tax_amount_minor     BIGINT NOT NULL DEFAULT 0,
    tax_rate_bps         INTEGER NOT NULL DEFAULT 0,
    tax_type             TEXT NOT NULL DEFAULT 'none',
    place_of_supply      TEXT NOT NULL DEFAULT '',
    invoice_number       TEXT,
    kind                 TEXT NOT NULL DEFAULT 'purchase',
    due_at               TIMESTAMPTZ,
    paid_at              TIMESTAMPTZ,
    payment_reference    TEXT NOT NULL DEFAULT '',
    billed_to            JSONB,
    supplier_gstin       TEXT NOT NULL DEFAULT '',
    sac                  TEXT NOT NULL DEFAULT '',
    emailed_at           TIMESTAMPTZ,
    CONSTRAINT invoices_kind_check CHECK (kind IN ('purchase', 'renewal')),
    CONSTRAINT invoices_status_check CHECK (status IN ('paid', 'open', 'void')),
    CONSTRAINT invoices_tax_type_check CHECK (tax_type IN
        ('none', 'gst_cgst_sgst', 'gst_igst', 'gst_zero_rated', 'vat_reverse_charge'))
);
CREATE INDEX idx_invoices_tenant ON tenant.invoices (tenant_id, issued_at DESC);
CREATE UNIQUE INDEX invoices_tenant_id_id_key ON tenant.invoices (tenant_id, id);
CREATE UNIQUE INDEX uq_invoices_invoice_number ON tenant.invoices (invoice_number);

-- internal/operations/billing
CREATE TABLE tenant.billing_checkouts (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    provider             TEXT NOT NULL,
    provider_ref         TEXT NOT NULL DEFAULT '',
    plan_code            TEXT NOT NULL,
    currency             TEXT NOT NULL,
    amount_minor         BIGINT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'pending',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at         TIMESTAMPTZ,
    taxable_amount_minor BIGINT NOT NULL DEFAULT 0,
    tax_amount_minor     BIGINT NOT NULL DEFAULT 0,
    tax_rate_bps         INTEGER NOT NULL DEFAULT 0,
    tax_type             TEXT NOT NULL DEFAULT 'none',
    place_of_supply      TEXT NOT NULL DEFAULT '',
    invoice_id           UUID,
    payment_method       JSONB,
    CONSTRAINT billing_checkouts_invoice_fkey FOREIGN KEY (tenant_id, invoice_id)
        REFERENCES tenant.invoices (tenant_id, id),
    CONSTRAINT billing_checkouts_status_check CHECK (status IN ('pending', 'completed', 'failed')),
    CONSTRAINT billing_checkouts_tax_type_check CHECK (tax_type IN
        ('none', 'gst_cgst_sgst', 'gst_igst', 'gst_zero_rated', 'vat_reverse_charge'))
);
CREATE INDEX idx_billing_checkouts_tenant ON tenant.billing_checkouts (tenant_id, created_at DESC);

-- internal/access/risk/ipallow
CREATE TABLE tenant.ip_rules (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    cidr       TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL DEFAULT 'allow',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ip_rules_action_check CHECK (action IN ('allow', 'deny'))
);
CREATE INDEX idx_ip_rules_tenant ON tenant.ip_rules (tenant_id);

-- internal/access/risk/ipallow
CREATE TABLE tenant.ip_rules_config (
    tenant_id  UUID PRIMARY KEY REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    enabled    BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- internal/federation/ldap
CREATE TABLE tenant.ldap_connections (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    server_url          TEXT NOT NULL,
    start_tls           BOOLEAN NOT NULL DEFAULT FALSE,
    skip_tls_verify     BOOLEAN NOT NULL DEFAULT FALSE,
    bind_dn             TEXT NOT NULL,
    base_dn             TEXT NOT NULL,
    user_filter         TEXT NOT NULL DEFAULT '(uid=%s)',
    email_attribute     TEXT NOT NULL DEFAULT 'mail',
    name_attribute      TEXT NOT NULL DEFAULT 'cn',
    status              TEXT NOT NULL DEFAULT 'draft',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at       TIMESTAMPTZ,
    bind_password_ct    BYTEA NOT NULL,
    bind_password_nonce BYTEA NOT NULL,
    encryption_version  SMALLINT NOT NULL DEFAULT 1,
    CONSTRAINT ldap_bind_secret_storage_valid CHECK (encryption_version = 1),
    CONSTRAINT ldap_connections_status_check CHECK (status IN ('draft', 'active', 'disabled'))
);
CREATE INDEX idx_ldap_conn_tenant ON tenant.ldap_connections (tenant_id);

-- internal/operations/siem
CREATE TABLE tenant.log_sinks (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    type               TEXT NOT NULL,
    endpoint           TEXT NOT NULL,
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    cursor_created_at  TIMESTAMPTZ,
    cursor_id          UUID,
    last_forwarded_at  TIMESTAMPTZ,
    last_error         TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    token_ct           BYTEA NOT NULL,
    token_nonce        BYTEA NOT NULL,
    encryption_version SMALLINT NOT NULL DEFAULT 1,
    leased_until       TIMESTAMPTZ,
    failures           INTEGER NOT NULL DEFAULT 0,
    next_attempt_at    TIMESTAMPTZ,
    CONSTRAINT log_sink_token_storage_valid CHECK (encryption_version = 1),
    CONSTRAINT log_sinks_failures_check CHECK (failures >= 0),
    CONSTRAINT log_sinks_type_check CHECK (type IN ('splunk_hec', 'datadog', 'http'))
);
CREATE INDEX idx_log_sinks_enabled ON tenant.log_sinks (enabled) WHERE enabled;
CREATE INDEX log_sinks_tenant_id_idx ON tenant.log_sinks (tenant_id);

-- internal/identity/domainverify
CREATE TABLE tenant.login_domain_checks (
    tenant_id  UUID PRIMARY KEY REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    host       TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL,
    result     JSONB NOT NULL
);

-- internal/identity/users
CREATE TABLE tenant.monthly_active_users (
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    month         DATE NOT NULL,
    user_id       UUID NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, month, user_id),
    CONSTRAINT monthly_active_users_month_check
        CHECK (month = (date_trunc('month', (month)::timestamp with time zone))::date)
);
CREATE INDEX monthly_active_users_month_idx ON tenant.monthly_active_users (month);

-- internal/federation/oidcsso
CREATE TABLE tenant.oidc_connections (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    name                   TEXT NOT NULL,
    issuer                 TEXT NOT NULL,
    discovery_url          TEXT NOT NULL DEFAULT '',
    client_id              TEXT NOT NULL,
    client_secret_ct       BYTEA NOT NULL,
    client_secret_nonce    BYTEA NOT NULL,
    encryption_version     SMALLINT NOT NULL DEFAULT 1,
    scopes                 TEXT[] NOT NULL DEFAULT ARRAY['openid', 'email', 'profile'],
    allowed_idp_tenant_ids TEXT[] NOT NULL DEFAULT '{}'::text[],
    email_claim            TEXT NOT NULL DEFAULT 'email',
    name_claim             TEXT NOT NULL DEFAULT 'name',
    given_name_claim       TEXT NOT NULL DEFAULT 'given_name',
    family_name_claim      TEXT NOT NULL DEFAULT 'family_name',
    groups_claim           TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL DEFAULT 'draft',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at          TIMESTAMPTZ,
    CONSTRAINT oidc_connections_status_check CHECK (status IN ('draft', 'active', 'disabled'))
);
CREATE INDEX idx_oidc_conn_tenant ON tenant.oidc_connections (tenant_id);

-- internal/operations/retention
CREATE TABLE tenant.retention_policy (
    tenant_id             UUID PRIMARY KEY REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    deleted_users_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_users_days    INTEGER NOT NULL DEFAULT 30,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by            UUID,
    CONSTRAINT retention_policy_deleted_users_days_check CHECK (
        deleted_users_days >= 1
        AND deleted_users_days <= 3650)
);

-- internal/federation/saml
CREATE TABLE tenant.saml_connections (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    idp_entity_id         TEXT NOT NULL,
    idp_sso_url           TEXT NOT NULL,
    idp_certificate       TEXT NOT NULL,
    email_attribute       TEXT NOT NULL DEFAULT '',
    name_attribute        TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL DEFAULT 'draft',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at         TIMESTAMPTZ,
    allow_idp_initiated   BOOLEAN NOT NULL DEFAULT FALSE,
    groups_attribute      TEXT NOT NULL DEFAULT '',
    metadata_url          TEXT,
    metadata_checked_at   TIMESTAMPTZ,
    metadata_refreshed_at TIMESTAMPTZ,
    metadata_error        TEXT,
    CONSTRAINT saml_connections_groups_attribute_check CHECK (char_length(groups_attribute) <= 256),
    CONSTRAINT saml_connections_status_check CHECK (status IN ('draft', 'active', 'disabled'))
);
CREATE UNIQUE INDEX saml_connections_tenant_id_id_key ON tenant.saml_connections (tenant_id, id);
COMMENT ON COLUMN tenant.saml_connections.allow_idp_initiated IS 'Accept unsolicited assertions with no InResponseTo. Replay IDs are still enforced.';

-- internal/federation/saml
CREATE TABLE tenant.saml_connection_certificates (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    connection_id UUID NOT NULL,
    certificate   TEXT NOT NULL,
    source        TEXT NOT NULL DEFAULT 'manual',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT saml_connection_certificates_tenant_id_connection_id_fkey FOREIGN KEY (tenant_id, connection_id)
        REFERENCES tenant.saml_connections (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT saml_connection_certificates_source_check CHECK (source IN ('manual', 'metadata'))
);
CREATE INDEX idx_saml_conn_certs_connection ON tenant.saml_connection_certificates (tenant_id, connection_id);

-- internal/federation/saml
CREATE TABLE tenant.saml_connection_keys (
    connection_id UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    certificate   TEXT NOT NULL,
    key_ct        BYTEA NOT NULL,
    key_nonce     BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT saml_connection_keys_tenant_id_connection_id_fkey FOREIGN KEY (tenant_id, connection_id)
        REFERENCES tenant.saml_connections (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX saml_connection_keys_tenant_id_idx ON tenant.saml_connection_keys (tenant_id);

-- internal/federation/saml
CREATE TABLE tenant.saml_service_providers (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    name                    TEXT NOT NULL,
    entity_id               TEXT NOT NULL,
    acs_url                 TEXT NOT NULL,
    name_id_format          TEXT NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    name_id_attribute       TEXT NOT NULL DEFAULT 'email',
    certificate             TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT 'draft',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at           TIMESTAMPTZ,
    attributes              JSONB NOT NULL DEFAULT '[{"name": "email", "source": "email"}, {"name": "name", "source": "display_name"}]'::jsonb,
    assignment_required     BOOLEAN NOT NULL DEFAULT FALSE,
    require_signed_requests BOOLEAN NOT NULL DEFAULT FALSE,
    encrypt_assertions      BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (tenant_id, entity_id),
    CONSTRAINT saml_service_providers_status_check CHECK (status IN ('draft', 'active', 'disabled'))
);
CREATE INDEX idx_saml_sp_entity ON tenant.saml_service_providers (entity_id);
CREATE UNIQUE INDEX saml_service_providers_tenant_id_id_key ON tenant.saml_service_providers (tenant_id, id);

-- internal/federation/saml
CREATE TABLE tenant.saml_idp_persistent_ids (
    tenant_id  UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    sp_id      UUID NOT NULL,
    user_id    UUID NOT NULL, -- account.users (0010)
    name_id    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, sp_id, user_id),
    UNIQUE (tenant_id, sp_id, name_id),
    CONSTRAINT saml_idp_persistent_ids_tenant_id_sp_id_fkey FOREIGN KEY (tenant_id, sp_id)
        REFERENCES tenant.saml_service_providers (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_saml_idp_persistent_ids_user ON tenant.saml_idp_persistent_ids (user_id);

-- internal/federation/saml
CREATE TABLE tenant.saml_sp_group_assignments (
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    sp_id       UUID NOT NULL,
    group_id    UUID NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID,
    PRIMARY KEY (tenant_id, sp_id, group_id),
    CONSTRAINT saml_sp_group_assignments_tenant_id_group_id_fkey FOREIGN KEY (tenant_id, group_id)
        REFERENCES tenant.groups (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT saml_sp_group_assignments_tenant_id_sp_id_fkey FOREIGN KEY (tenant_id, sp_id)
        REFERENCES tenant.saml_service_providers (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_saml_sp_group_assignments_group ON tenant.saml_sp_group_assignments (tenant_id, group_id);

-- internal/federation/saml
CREATE TABLE tenant.saml_sp_user_assignments (
    tenant_id   UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    sp_id       UUID NOT NULL,
    user_id     UUID NOT NULL, -- account.users (0010)
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID,
    PRIMARY KEY (tenant_id, sp_id, user_id),
    CONSTRAINT saml_sp_user_assignments_tenant_id_sp_id_fkey FOREIGN KEY (tenant_id, sp_id)
        REFERENCES tenant.saml_service_providers (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_saml_sp_user_assignments_user ON tenant.saml_sp_user_assignments (user_id);

-- internal/federation/scim
CREATE TABLE tenant.scim_tokens (
    tenant_id    UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    id           UUID NOT NULL DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL DEFAULT 'SCIM token',
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    replaced_by  UUID,
    created_by   UUID,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT scim_tokens_replaced_by_fkey FOREIGN KEY (tenant_id, replaced_by)
        REFERENCES tenant.scim_tokens (tenant_id, id) ON DELETE SET NULL (replaced_by),
    CONSTRAINT scim_tokens_name_check CHECK (char_length(name) >= 1 AND char_length(name) <= 200)
);
CREATE UNIQUE INDEX uq_scim_token_hash ON tenant.scim_tokens (token_hash);

-- internal/developer/credentials/secrets
CREATE TABLE tenant.secrets (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    name                     TEXT NOT NULL,
    scope                    TEXT NOT NULL DEFAULT '',
    ciphertext               BYTEA NOT NULL,
    nonce                    BYTEA NOT NULL,
    last4                    TEXT NOT NULL DEFAULT '',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    encryption_version       SMALLINT NOT NULL DEFAULT 1,
    last_revealed_at         TIMESTAMPTZ,
    last_revealed_by         UUID,
    last_revealed_credential TEXT,
    value_changed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotation_interval_days   INTEGER,
    UNIQUE (tenant_id, name),
    CONSTRAINT secrets_rotation_interval_days_check CHECK (
        rotation_interval_days >= 1
        AND rotation_interval_days <= 3650)
);

-- internal/access/authorization/policy
CREATE TABLE tenant.security_policies (
    tenant_id            UUID PRIMARY KEY REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    session_max_age      INTERVAL NOT NULL DEFAULT INTERVAL '30 days',
    mfa_enforcement      TEXT NOT NULL DEFAULT 'optional',
    settings             JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_idle_timeout INTERVAL NOT NULL DEFAULT INTERVAL '24 hours',
    max_sessions         INTEGER,
    session_limit_action TEXT NOT NULL DEFAULT 'evict_oldest',
    mfa_grace_days       INTEGER NOT NULL DEFAULT 0,
    mfa_enforced_since   TIMESTAMPTZ,
    step_up_window       INTERVAL NOT NULL DEFAULT INTERVAL '5 minutes',
    step_up_methods      TEXT[],
    CONSTRAINT security_policies_max_sessions_check CHECK (max_sessions >= 1 AND max_sessions <= 1000),
    CONSTRAINT security_policies_mfa_enforcement_check CHECK (mfa_enforcement IN (
            'optional', 'required', 'admin_only')),
    CONSTRAINT security_policies_mfa_grace_days_check CHECK (mfa_grace_days >= 0 AND mfa_grace_days <= 90),
    CONSTRAINT security_policies_session_limit_action_check CHECK (session_limit_action IN (
            'evict_oldest', 'refuse')),
    CONSTRAINT security_policies_step_up_methods_check CHECK (
        step_up_methods IS NULL
        OR (cardinality(step_up_methods) > 0 AND step_up_methods <@ ARRAY['totp', 'recovery_code', 'otp', 'webauthn', 'push'])),
    CONSTRAINT security_policies_step_up_window_check CHECK (
        step_up_window >= INTERVAL '1 minute'
        AND step_up_window <= INTERVAL '1 hour')
);

-- internal/operations/billing
CREATE TABLE tenant.signup_checkouts (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID NOT NULL,
    org_name             TEXT NOT NULL,
    org_slug             TEXT NOT NULL,
    region               TEXT NOT NULL DEFAULT '',
    plan_code            TEXT NOT NULL,
    currency             TEXT NOT NULL,
    country              TEXT NOT NULL DEFAULT '',
    provider             TEXT NOT NULL,
    provider_ref         TEXT NOT NULL DEFAULT '',
    amount_minor         BIGINT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'pending',
    tenant_id            UUID REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at         TIMESTAMPTZ,
    taxable_amount_minor BIGINT NOT NULL DEFAULT 0,
    tax_amount_minor     BIGINT NOT NULL DEFAULT 0,
    tax_rate_bps         INTEGER NOT NULL DEFAULT 0,
    tax_type             TEXT NOT NULL DEFAULT 'none',
    place_of_supply      TEXT NOT NULL DEFAULT '',
    payment_method       JSONB,
    CONSTRAINT signup_checkouts_status_check CHECK (status IN ('pending', 'completed', 'failed')),
    CONSTRAINT signup_checkouts_tax_type_check CHECK (tax_type IN
        ('none', 'gst_cgst_sgst', 'gst_igst', 'gst_zero_rated', 'vat_reverse_charge'))
);
CREATE INDEX idx_signup_checkouts_user ON tenant.signup_checkouts (user_id, created_at DESC);
CREATE INDEX signup_checkouts_tenant_id_idx ON tenant.signup_checkouts (tenant_id);

-- internal/federation/social
CREATE TABLE tenant.social_providers (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    provider            TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    discovery_url       TEXT,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_secret_ct    BYTEA NOT NULL,
    client_secret_nonce BYTEA NOT NULL,
    encryption_version  SMALLINT NOT NULL DEFAULT 1,
    apple_team_id       TEXT,
    apple_key_id        TEXT,
    CONSTRAINT social_provider_secret_storage_valid CHECK (encryption_version = 1)
);
CREATE UNIQUE INDEX uq_social_tenant_provider ON tenant.social_providers (tenant_id, provider);

-- internal/federation/ssosync
CREATE TABLE tenant.sso_group_mappings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    connection_id UUID NOT NULL,
    idp_group     TEXT NOT NULL,
    group_id      UUID NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT sso_group_mappings_group_id_fkey FOREIGN KEY (tenant_id, group_id)
        REFERENCES tenant.groups (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT sso_group_mappings_idp_group_check CHECK (
        char_length(idp_group) >= 1
        AND char_length(idp_group) <= 1024)
);
CREATE UNIQUE INDEX sso_group_mappings_value
    ON tenant.sso_group_mappings (tenant_id, connection_id, lower(idp_group), group_id);

-- internal/operations/billing
CREATE TABLE tenant.subscriptions (
    tenant_id            UUID PRIMARY KEY REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    plan_id              UUID NOT NULL, -- platform.billing_plans (0010)
    currency             TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'active',
    current_period_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_period_end   TIMESTAMPTZ NOT NULL,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    trial_end            TIMESTAMPTZ,
    ended_at             TIMESTAMPTZ,
    CONSTRAINT subscriptions_currency_check CHECK (currency ~ '^[A-Z]{3}$'),
    CONSTRAINT subscriptions_status_check CHECK (status IN ('active', 'trialing', 'canceled', 'past_due'))
);
CREATE INDEX idx_subscriptions_due ON tenant.subscriptions (current_period_end)
    WHERE status IN ('active', 'past_due', 'trialing');

-- internal/developer/credentials/tokenvault
CREATE TABLE tenant.token_vault_connect_states (
    state         TEXT PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    user_id       UUID NOT NULL, -- account.users (0010)
    provider      TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    code_verifier TEXT
);
CREATE INDEX token_vault_connect_states_tenant_id_idx ON tenant.token_vault_connect_states (tenant_id);

-- internal/developer/credentials/tokenvault
CREATE TABLE tenant.token_vault_grants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    user_id             UUID NOT NULL, -- account.users (0010)
    provider            TEXT NOT NULL,
    external_account_id TEXT,
    access_token_ct     BYTEA NOT NULL,
    access_token_nonce  BYTEA NOT NULL,
    refresh_token_ct    BYTEA,
    refresh_token_nonce BYTEA,
    token_type          TEXT NOT NULL DEFAULT 'Bearer',
    scope               TEXT,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    encryption_version  SMALLINT NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, user_id, provider)
);

-- internal/developer/credentials/tokenvault
CREATE TABLE tenant.token_vault_providers (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    provider            TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    authorize_url       TEXT NOT NULL,
    token_url           TEXT NOT NULL,
    scopes              TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_secret_ct    BYTEA NOT NULL,
    client_secret_nonce BYTEA NOT NULL,
    encryption_version  SMALLINT NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, provider),
    CONSTRAINT token_vault_provider_secret_storage_valid CHECK (encryption_version = 1)
);

-- internal/developer/webhooks
CREATE TABLE tenant.webhook_subscriptions (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                  UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    url                        TEXT NOT NULL,
    events                     TEXT[] NOT NULL DEFAULT '{}'::text[],
    disabled_at                TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    secret_ct                  BYTEA NOT NULL,
    secret_nonce               BYTEA NOT NULL,
    encryption_version         SMALLINT NOT NULL DEFAULT 1,
    failing_since              TIMESTAMPTZ,
    disabled_reason            TEXT,
    previous_secret_ct         BYTEA,
    previous_secret_nonce      BYTEA,
    previous_secret_expires_at TIMESTAMPTZ,
    disabled_by                UUID,
    created_by                 UUID,
    CONSTRAINT webhook_previous_secret_complete CHECK (
        (previous_secret_ct IS NULL) = (previous_secret_nonce IS NULL)
        AND (previous_secret_ct IS NULL) = (previous_secret_expires_at IS NULL)),
    CONSTRAINT webhook_secret_storage_valid CHECK (encryption_version = 1),
    CONSTRAINT webhook_subscriptions_disabled_reason_check CHECK (disabled_reason IN ('disabled', 'failing'))
);
CREATE INDEX idx_webhook_tenant ON tenant.webhook_subscriptions (tenant_id);

-- internal/developer/webhooks
CREATE TABLE tenant.webhook_deliveries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID NOT NULL REFERENCES tenant.webhook_subscriptions (id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status_code     INTEGER,
    response_body   TEXT,
    error           TEXT,
    attempt         INTEGER NOT NULL DEFAULT 0,
    delivered_at    TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dead_at         TIMESTAMPTZ,
    lease_owner     UUID,
    lease_until     TIMESTAMPTZ,
    event_id        UUID NOT NULL,
    CONSTRAINT webhook_deliveries_subscription_event_key UNIQUE (subscription_id, event_id)
);
CREATE INDEX idx_webhook_deliv_pending ON tenant.webhook_deliveries (next_attempt_at)
    WHERE delivered_at IS NULL;
CREATE INDEX idx_webhook_deliveries_sub_pending ON tenant.webhook_deliveries (subscription_id, next_attempt_at)
    WHERE delivered_at IS NULL;
CREATE INDEX webhook_delivery_lease_due ON tenant.webhook_deliveries (lease_until, next_attempt_at)
    WHERE delivered_at IS NULL AND dead_at IS NULL;

-- internal/developer/webhooks
CREATE TABLE tenant.webhook_delivery_attempts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    delivery_id  UUID NOT NULL REFERENCES tenant.webhook_deliveries (id) ON DELETE CASCADE,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status_code  INTEGER,
    duration_ms  INTEGER NOT NULL,
    error        TEXT
);
CREATE INDEX idx_webhook_delivery_attempts_delivery
    ON tenant.webhook_delivery_attempts (delivery_id, attempted_at);
CREATE INDEX webhook_delivery_attempts_tenant_id_idx ON tenant.webhook_delivery_attempts (tenant_id);
