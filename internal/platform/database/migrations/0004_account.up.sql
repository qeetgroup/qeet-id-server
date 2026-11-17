-- 0004_account — accounts: the people who sign in, and what belongs to a person
-- across organisations.
--
-- Each table is headed by the package that owns it. A column marked (0010) is a
-- foreign key into another schema, which 0010_cross_schema_keys adds.

-- internal/identity/users
-- tenant_id is the home organisation. Its key doesn't cascade: the
-- organisation purge erases each account, or detaches one that is a member
-- elsewhere, first.
CREATE TABLE account.users (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID, -- tenant.tenants (0010)
    email             TEXT NOT NULL,
    email_verified_at TIMESTAMPTZ,
    phone             TEXT,
    phone_verified_at TIMESTAMPTZ,
    display_name      TEXT,
    status            TEXT NOT NULL DEFAULT 'active',
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at        TIMESTAMPTZ,
    mfa_required      BOOLEAN NOT NULL DEFAULT FALSE,
    external_id       TEXT,
    provisioned_via   TEXT,
    avatar_url        TEXT,
    suspended_at      TIMESTAMPTZ,
    suspension_reason TEXT,
    suspension_source TEXT,
    suspension_risk   TEXT,
    suspension_review TEXT,
    deleted_by        UUID REFERENCES account.users (id) ON DELETE SET NULL,
    UNIQUE (id, tenant_id),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'invited', 'suspended', 'deleted')),
    CONSTRAINT users_suspension_reason_check CHECK (suspension_reason IN (
            'unspecified', 'provider', 'suspicious_activity', 'policy_violation', 'account_compromise',
            'offboarding', 'inactive', 'other')),
    CONSTRAINT users_suspension_review_check CHECK (suspension_review IN ('pending', 'reviewed')),
    CONSTRAINT users_suspension_risk_check CHECK (suspension_risk IN ('unknown', 'low', 'medium', 'high')),
    CONSTRAINT users_suspension_source_check CHECK (suspension_source IN (
            'unknown', 'manual', 'scim', 'ldap', 'policy'))
);
CREATE INDEX idx_users_scim_external ON account.users (tenant_id, external_id)
    WHERE provisioned_via = 'scim' AND deleted_at IS NULL;
CREATE INDEX idx_users_tenant_status ON account.users (tenant_id, status) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_users_email_global ON account.users (lower(email)) WHERE deleted_at IS NULL;
CREATE INDEX users_suspended_tenant ON account.users (tenant_id, suspended_at DESC, id)
    WHERE status = 'suspended' AND deleted_at IS NULL;

-- internal/identity/verification
CREATE TABLE account.email_verifications (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES account.users (id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts   INTEGER NOT NULL DEFAULT 0,
    purpose    TEXT NOT NULL,
    CONSTRAINT email_verifications_purpose_check CHECK (purpose IN ('verify_email', 'change_email'))
);
CREATE INDEX idx_email_verif_user ON account.email_verifications (user_id, created_at DESC);

-- internal/operations/gdpr
CREATE TABLE account.export_requests (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL, -- tenant.tenants (0010)
    user_id      UUID REFERENCES account.users (id) ON DELETE SET NULL,
    requested_by UUID,
    status       TEXT NOT NULL DEFAULT 'pending',
    payload      JSONB,
    error        TEXT,
    completed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_owner  UUID,
    lease_until  TIMESTAMPTZ,
    subject_id   UUID NOT NULL,
    CONSTRAINT export_requests_user_tenant_fkey FOREIGN KEY (user_id, tenant_id)
        REFERENCES account.users (id, tenant_id) ON DELETE SET NULL (user_id),
    CONSTRAINT export_requests_status_check CHECK (status IN ('pending', 'ready', 'failed', 'expired')),
    CONSTRAINT export_requests_subject_check CHECK (user_id IS NULL OR user_id = subject_id)
);
CREATE INDEX export_request_lease_due ON account.export_requests (lease_until, created_at)
    WHERE status = 'pending';
CREATE INDEX idx_export_requests_pending ON account.export_requests (status) WHERE status = 'pending';
CREATE INDEX idx_export_requests_tenant ON account.export_requests (tenant_id, created_at DESC);

-- internal/federation/social
CREATE TABLE account.external_identities (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES account.users (id) ON DELETE CASCADE,
    tenant_id     UUID NOT NULL, -- tenant.tenants (0010)
    provider      TEXT NOT NULL,
    subject       TEXT NOT NULL,
    email         TEXT,
    metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
    linked_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    connection_id UUID
);
CREATE UNIQUE INDEX uq_ext_identity_provider
    ON account.external_identities (tenant_id, provider, connection_id, subject) NULLS NOT DISTINCT;

-- internal/identity/verification
CREATE TABLE account.phone_verifications (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES account.users (id) ON DELETE CASCADE,
    phone      TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_phone_verif_user ON account.phone_verifications (user_id, created_at DESC);

-- internal/operations/gdpr
CREATE TABLE account.purge_requests (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL, -- tenant.tenants (0010)
    user_id           UUID REFERENCES account.users (id) ON DELETE SET NULL,
    requested_by      UUID,
    reason            TEXT,
    status            TEXT NOT NULL DEFAULT 'pending',
    grace_until       TIMESTAMPTZ NOT NULL,
    completed_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    quarantined_at    TIMESTAMPTZ,
    quarantine_reason TEXT,
    lease_owner       UUID,
    lease_until       TIMESTAMPTZ,
    subject_id        UUID NOT NULL,
    subject_email     TEXT,
    subject_name      TEXT,
    CONSTRAINT purge_requests_user_tenant_fkey FOREIGN KEY (user_id, tenant_id)
        REFERENCES account.users (id, tenant_id) ON DELETE SET NULL (user_id),
    CONSTRAINT purge_requests_status_check CHECK (status IN (
            'pending', 'completed', 'cancelled', 'quarantined')),
    CONSTRAINT purge_requests_subject_check CHECK (user_id IS NULL OR user_id = subject_id)
);
CREATE INDEX idx_purge_pending ON account.purge_requests (grace_until) WHERE status = 'pending';
CREATE INDEX purge_request_lease_due ON account.purge_requests (lease_until, grace_until)
    WHERE status = 'pending';
CREATE INDEX purge_requests_tenant_id_idx ON account.purge_requests (tenant_id);
