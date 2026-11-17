-- 0003_platform — what the platform itself keeps, for no one organization:
-- signing keys, jobs, the outbox, billing plans, audit checkpoints.
--
-- Each table is headed by the package that owns it. A column marked (0010) is a
-- foreign key into another schema, which 0010_cross_schema_keys adds.

-- internal/operations/audit
CREATE TABLE platform.audit_chain_checkpoints (
    organization_id  UUID, -- organization.organizations (0010)
    event_id         UUID PRIMARY KEY,
    event_created_at TIMESTAMPTZ NOT NULL,
    row_hash         CHAR(64) NOT NULL,
    verified_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    broken_at        TIMESTAMPTZ,
    chain_shard      SMALLINT NOT NULL DEFAULT 0,
    key_id           TEXT,
    mac              BYTEA,
    CONSTRAINT audit_chain_checkpoints_organization_id_chain_shard_key UNIQUE NULLS NOT DISTINCT (organization_id, chain_shard)
);

-- internal/operations/audit
CREATE TABLE platform.audit_purge_checkpoints (
    organization_id  UUID PRIMARY KEY, -- organization.organizations (0010)
    event_id         UUID NOT NULL,
    event_created_at TIMESTAMPTZ NOT NULL,
    row_hash         CHAR(64) NOT NULL,
    events_purged    BIGINT NOT NULL DEFAULT 0,
    purged_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    key_id           TEXT,
    mac              BYTEA
);

-- internal/operations/audit
CREATE TABLE platform.audit_verification_runs (
    id                     UUID PRIMARY KEY,
    started_at             TIMESTAMPTZ NOT NULL,
    finished_at            TIMESTAMPTZ NOT NULL,
    scope                  TEXT NOT NULL DEFAULT 'all',
    organizations_walked   INTEGER NOT NULL,
    rows_checked           BIGINT NOT NULL,
    outcome                TEXT NOT NULL,
    broken_organization_id UUID,
    first_broken_link      UUID,
    broken_reason          TEXT,
    error                  TEXT,
    CONSTRAINT audit_verification_runs_outcome_check CHECK (outcome IN ('intact', 'broken', 'error'))
);
CREATE INDEX audit_verification_runs_started_idx ON platform.audit_verification_runs (started_at DESC);

-- internal/operations/billing
CREATE TABLE platform.billing_plans (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    "interval"  TEXT NOT NULL DEFAULT 'month',
    features    JSONB NOT NULL DEFAULT '[]'::jsonb,
    sort        INTEGER NOT NULL DEFAULT 0,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT billing_plans_interval_check CHECK ("interval" IN ('month', 'year'))
);

-- internal/operations/billing
CREATE TABLE platform.billing_plan_prices (
    plan_id      UUID NOT NULL REFERENCES platform.billing_plans (id) ON DELETE CASCADE,
    currency     TEXT NOT NULL,
    amount_minor BIGINT NOT NULL,
    PRIMARY KEY (plan_id, currency),
    CONSTRAINT billing_plan_prices_amount_minor_check CHECK (amount_minor >= 0),
    CONSTRAINT billing_plan_prices_currency_check CHECK (currency ~ '^[A-Z]{3}$')
);

-- internal/platform/messaging/delivery
CREATE TABLE platform.email_messages (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID, -- organization.organizations (0010)
    to_hash             TEXT NOT NULL,
    to_hint             TEXT NOT NULL,
    template            TEXT NOT NULL DEFAULT '',
    provider            TEXT NOT NULL,
    provider_message_id TEXT,
    status              TEXT NOT NULL,
    status_reason       TEXT NOT NULL DEFAULT '',
    sent_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT email_messages_status_check CHECK (status IN (
            'sent', 'delivered', 'bounced', 'complained', 'suppressed', 'failed'))
);
CREATE UNIQUE INDEX email_messages_provider_id_idx ON platform.email_messages (provider, provider_message_id)
    WHERE provider_message_id IS NOT NULL;
CREATE INDEX email_messages_sent_at_idx ON platform.email_messages (sent_at);
CREATE INDEX email_messages_organization_to_idx ON platform.email_messages (organization_id, to_hash, sent_at DESC);

-- internal/platform/messaging/delivery
CREATE TABLE platform.email_suppressions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID, -- organization.organizations (0010)
    address_hash    TEXT NOT NULL,
    address_hint    TEXT NOT NULL,
    reason          TEXT NOT NULL,
    detail          TEXT NOT NULL DEFAULT '',
    message_id      UUID REFERENCES platform.email_messages (id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cleared_at      TIMESTAMPTZ,
    cleared_by      UUID,
    CONSTRAINT email_suppressions_reason_check CHECK (reason IN ('bounce', 'complaint'))
);
CREATE UNIQUE INDEX email_suppressions_active_idx ON platform.email_suppressions (address_hash)
    WHERE cleared_at IS NULL;
CREATE INDEX email_suppressions_organization_idx ON platform.email_suppressions (organization_id, created_at DESC);

-- internal/platform/http/idempotency
CREATE TABLE platform.idempotency_keys (
    scope        TEXT NOT NULL,
    key          TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status       INTEGER,
    content_type TEXT,
    body_enc     BYTEA,
    body_nonce   BYTEA,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    attempt      UUID,
    PRIMARY KEY (scope, key)
);
CREATE INDEX idx_idempotency_keys_created ON platform.idempotency_keys (created_at);

-- internal/operations/servicehealth
CREATE TABLE platform.incidents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component   TEXT NOT NULL,
    impact      TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    CONSTRAINT incidents_component_check CHECK (component IN (
            'api', 'sign_in', 'email', 'webhooks', 'directory')),
    CONSTRAINT incidents_impact_check CHECK (impact IN ('maintenance', 'degraded', 'outage')),
    CONSTRAINT incidents_title_check CHECK (char_length(title) >= 1 AND char_length(title) <= 200)
);
CREATE INDEX incidents_started_idx ON platform.incidents (started_at DESC);

-- internal/operations/billing
CREATE TABLE platform.invoice_number_series (
    financial_year TEXT PRIMARY KEY,
    last_number    BIGINT NOT NULL
);

-- internal/platform/crypto/tokens
CREATE TABLE platform.jwt_signing_keys (
    kid                TEXT PRIMARY KEY,
    algorithm          TEXT NOT NULL,
    state              TEXT NOT NULL,
    public_key_pem     TEXT NOT NULL,
    private_key_ct     BYTEA,
    private_key_nonce  BYTEA,
    encryption_version SMALLINT NOT NULL DEFAULT 1,
    activated_at       TIMESTAMPTZ,
    retire_at          TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT jwt_signing_keys_algorithm_check CHECK (algorithm IN ('ES256', 'RS256')),
    CONSTRAINT jwt_signing_keys_encryption_version_check CHECK (encryption_version = 1),
    CONSTRAINT jwt_signing_keys_state_check CHECK (state IN ('candidate', 'active', 'retired')),
    CONSTRAINT jwt_signing_private_storage_valid CHECK (
        (state IN ('candidate', 'active') AND private_key_ct IS NOT NULL AND private_key_nonce IS NOT NULL)
        OR (state = 'retired' AND private_key_ct IS NULL AND private_key_nonce IS NULL AND retire_at IS NOT NULL))
);
CREATE UNIQUE INDEX jwt_signing_one_active ON platform.jwt_signing_keys (state) WHERE state = 'active';
CREATE INDEX jwt_signing_retirement ON platform.jwt_signing_keys (retire_at) WHERE state = 'retired';

-- internal/platform/events/outbox
CREATE TABLE platform.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_id    UUID NOT NULL,
    topic           TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at    TIMESTAMPTZ,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    last_attempt_at TIMESTAMPTZ,
    lease_owner     UUID,
    lease_until     TIMESTAMPTZ
);
CREATE INDEX idx_outbox_retry_eligible ON platform.outbox (last_attempt_at NULLS FIRST)
    WHERE published_at IS NULL;
CREATE INDEX idx_outbox_unpublished ON platform.outbox (created_at) WHERE published_at IS NULL;
CREATE INDEX outbox_lease_due ON platform.outbox (lease_until, created_at) WHERE published_at IS NULL;

-- internal/platform/events/outbox
CREATE TABLE platform.outbox_dead_letter (
    id               UUID PRIMARY KEY,
    aggregate_id     UUID NOT NULL,
    topic            TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    payload          JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    attempts         INTEGER NOT NULL,
    last_error       TEXT,
    dead_lettered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_outbox_dlq_dead_lettered_at ON platform.outbox_dead_letter (dead_lettered_at DESC);

-- internal/operations/ratelimits
CREATE TABLE platform.rate_limit_overrides (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL, -- organization.organizations (0010)
    limit_key       TEXT NOT NULL,
    rate            DOUBLE PRECISION NOT NULL,
    capacity        INTEGER NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, limit_key),
    CONSTRAINT rate_limit_overrides_capacity_check CHECK (capacity > 0),
    CONSTRAINT rate_limit_overrides_limit_key_check CHECK (limit_key IN ('tenant', 'user', 'api_key')),
    CONSTRAINT rate_limit_overrides_rate_check CHECK (rate > (0)::double precision)
);

-- internal/operations/sales
CREATE TABLE platform.sales_leads (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID, -- organization.organizations (0010)
    user_id         UUID,
    name            TEXT NOT NULL DEFAULT '',
    email           TEXT NOT NULL,
    company         TEXT NOT NULL DEFAULT '',
    team_size       TEXT NOT NULL DEFAULT '',
    message         TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'new',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_sales_leads_created ON platform.sales_leads (created_at DESC);
CREATE INDEX sales_leads_organization_id_idx ON platform.sales_leads (organization_id);

-- internal/platform/worker
CREATE TABLE platform.scheduled_job_runs (
    job               TEXT PRIMARY KEY,
    last_started_at   TIMESTAMPTZ NOT NULL,
    last_finished_at  TIMESTAMPTZ,
    last_succeeded_at TIMESTAMPTZ,
    last_error        TEXT
);

-- internal/operations/gdpr
-- The record of a purged organization, kept after it is gone: organization_id has
-- no foreign key.
CREATE TABLE platform.organization_purges (
    organization_id   UUID PRIMARY KEY,
    slug              TEXT NOT NULL,
    deleted_at        TIMESTAMPTZ NOT NULL,
    purged_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rows_purged       JSONB NOT NULL DEFAULT '{}'::jsonb,
    accounts_removed  INTEGER NOT NULL DEFAULT 0,
    accounts_detached INTEGER NOT NULL DEFAULT 0
);
