-- 0007_auth — sign-in: sessions, credentials, second factors, applications,
-- tokens and codes.
--
-- Each table is headed by the package that owns it. A column marked (0010) is a
-- foreign key into another schema, which 0010_cross_schema_keys adds.

-- internal/access/authorization/abac
CREATE TABLE auth.abac_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL, -- organization.organizations (0010)
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    effect          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    action          TEXT NOT NULL,
    condition       JSONB NOT NULL DEFAULT '{}'::jsonb,
    priority        INTEGER NOT NULL DEFAULT 0,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version         INTEGER NOT NULL DEFAULT 1,
    updated_by      UUID,
    UNIQUE (organization_id, name),
    CONSTRAINT abac_policies_effect_check CHECK (effect IN ('allow', 'deny'))
);
CREATE UNIQUE INDEX abac_policies_organization_id_id_key ON auth.abac_policies (organization_id, id);
CREATE INDEX idx_abac_policies_lookup ON auth.abac_policies (organization_id, resource_type, action);

-- internal/access/authorization/abac
CREATE TABLE auth.abac_policy_versions (
    organization_id UUID NOT NULL, -- organization.organizations (0010)
    policy_id       UUID NOT NULL,
    version         INTEGER NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL,
    effect          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    action          TEXT NOT NULL,
    condition       JSONB NOT NULL,
    priority        INTEGER NOT NULL,
    enabled         BOOLEAN NOT NULL,
    saved_by        UUID,
    saved_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, policy_id, version),
    CONSTRAINT abac_policy_versions_organization_id_policy_id_fkey FOREIGN KEY (organization_id, policy_id)
        REFERENCES auth.abac_policies (organization_id, id) ON DELETE CASCADE,
    CONSTRAINT abac_policy_versions_version_check CHECK (version >= 1),
    CONSTRAINT abac_policy_versions_effect_check CHECK (effect IN ('allow', 'deny'))
);

-- internal/federation/adminportal
CREATE TABLE auth.admin_portal_sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    link_id      UUID NOT NULL, -- organization.admin_portal_links (0010)
    token_hash   TEXT NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX admin_portal_sessions_expiry ON auth.admin_portal_sessions (expires_at) WHERE revoked_at IS NULL;
CREATE INDEX admin_portal_sessions_link ON auth.admin_portal_sessions (link_id);

-- internal/developer/agents
CREATE TABLE auth.agents (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id            UUID NOT NULL, -- organization.organizations (0010)
    name                       TEXT NOT NULL,
    secret_hash                TEXT NOT NULL,
    scopes                     TEXT[] NOT NULL DEFAULT '{}'::text[],
    token_ttl_seconds          INTEGER NOT NULL DEFAULT 600,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status                     TEXT NOT NULL DEFAULT 'active',
    sponsor_user_id            UUID, -- account.users (0010)
    last_used_at               TIMESTAMPTZ,
    previous_secret_hash       TEXT,
    previous_secret_expires_at TIMESTAMPTZ,
    CONSTRAINT agents_status_check CHECK (status IN ('active', 'suspended', 'decommissioned'))
);
CREATE INDEX idx_agents_sponsor ON auth.agents (organization_id, sponsor_user_id);
CREATE INDEX idx_agents_organization_status ON auth.agents (organization_id, status);

-- internal/developer/api-keys
CREATE TABLE auth.api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL, -- organization.organizations (0010)
    user_id         UUID, -- account.users (0010)
    name            TEXT NOT NULL,
    prefix          TEXT NOT NULL,
    key_hash        TEXT NOT NULL,
    scopes          TEXT[] NOT NULL DEFAULT '{}'::text[],
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID,
    rotated_from    UUID
);
CREATE INDEX idx_api_keys_prefix ON auth.api_keys (prefix) WHERE revoked_at IS NULL;
CREATE INDEX idx_api_keys_organization ON auth.api_keys (organization_id);

-- internal/access/authorization/decisionlog
CREATE TABLE auth.authz_decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL, -- organization.organizations (0010)
    decided_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source          TEXT NOT NULL,
    caller_type     TEXT NOT NULL DEFAULT '',
    caller_id       UUID,
    caller_client   TEXT NOT NULL DEFAULT '',
    subject         TEXT NOT NULL,
    resource        TEXT NOT NULL DEFAULT '',
    action          TEXT NOT NULL DEFAULT '',
    allowed         BOOLEAN NOT NULL,
    model           TEXT NOT NULL DEFAULT '',
    rule            TEXT NOT NULL DEFAULT '',
    reason_code     TEXT NOT NULL DEFAULT '',
    CONSTRAINT authz_decisions_source_check CHECK (source IN (
            'check', 'relation_check', 'authzen', 'abac_evaluate', 'abac_draft'))
);
CREATE INDEX authz_decisions_decided_idx ON auth.authz_decisions (decided_at);
CREATE INDEX authz_decisions_organization_idx ON auth.authz_decisions (organization_id, decided_at DESC, id DESC);

-- internal/access/threat/bot
-- An append-only log: organization_id has no foreign key, so recording never locks
-- the organization's row. The organization purge deletes its rows in batches.
CREATE TABLE auth.bot_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    ip              INET,
    user_agent      TEXT NOT NULL DEFAULT '',
    score           REAL NOT NULL,
    verdict         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id         UUID
);
CREATE INDEX idx_bot_events_organization_created ON auth.bot_events (organization_id, created_at DESC);

-- internal/access/threat/bot
CREATE TABLE auth.bot_settings (
    organization_id UUID PRIMARY KEY, -- organization.organizations (0010)
    ua_check        BOOLEAN NOT NULL DEFAULT TRUE,
    honeypot        BOOLEAN NOT NULL DEFAULT TRUE,
    captcha         BOOLEAN NOT NULL DEFAULT FALSE,
    signature       BOOLEAN NOT NULL DEFAULT FALSE,
    score_threshold REAL NOT NULL DEFAULT 0.70,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- internal/developer/credentials/vc
CREATE TABLE auth.credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL, -- organization.organizations (0010)
    subject         TEXT NOT NULL,
    type            TEXT NOT NULL,
    claims          JSONB NOT NULL DEFAULT '{}'::jsonb,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    user_id         UUID -- account.users (0010)
);
CREATE INDEX idx_credentials_organization ON auth.credentials (organization_id, issued_at DESC);

-- internal/access/authentication
CREATE TABLE auth.login_attempts (
    email           TEXT PRIMARY KEY,
    failed_count    INTEGER NOT NULL DEFAULT 0,
    first_failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_failed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until    TIMESTAMPTZ
);
CREATE INDEX login_attempts_last_failed_at_idx ON auth.login_attempts (last_failed_at);

-- internal/access/authentication
CREATE TABLE auth.login_attempts_by_network (
    email           TEXT NOT NULL,
    network         TEXT NOT NULL,
    failed_count    INTEGER NOT NULL,
    first_failed_at TIMESTAMPTZ NOT NULL,
    last_failed_at  TIMESTAMPTZ NOT NULL,
    locked_until    TIMESTAMPTZ,
    PRIMARY KEY (email, network)
);
CREATE INDEX login_attempts_by_network_last_failed_at_idx ON auth.login_attempts_by_network (last_failed_at);

-- internal/federation/saml, internal/federation/oidcsso, internal/federation/social
-- A one-time code a federated sign-in hands the hosted login, which exchanges
-- it for a session. kind names the flow that issued it, and only that flow's
-- exchange accepts it.
CREATE TABLE auth.login_codes (
    code_hash       TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    user_id         UUID NOT NULL, -- account.users (0010)
    organization_id UUID, -- organization.organizations (0010)
    connection_id   UUID,
    provider        TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT login_codes_kind_check CHECK (
        (kind = 'saml' AND organization_id IS NOT NULL AND connection_id IS NOT NULL AND provider IS NULL)
        OR (kind = 'oidc_connection' AND organization_id IS NOT NULL AND connection_id IS NOT NULL AND provider IS NULL)
        OR (kind = 'social' AND organization_id IS NOT NULL AND connection_id IS NULL AND provider IS NOT NULL)
        OR (kind = 'platform_social' AND organization_id IS NULL AND connection_id IS NULL AND provider IS NULL))
);
CREATE INDEX login_codes_expires_at_idx ON auth.login_codes (expires_at);
CREATE INDEX login_codes_organization_id_idx ON auth.login_codes (organization_id);

-- internal/access/threat/risk
CREATE TABLE auth.login_context_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL, -- organization.organizations (0010)
    user_id         UUID NOT NULL, -- account.users (0010)
    device_key      TEXT NOT NULL,
    country         TEXT,
    seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_login_context_user_device ON auth.login_context_history (user_id, device_key);
CREATE INDEX idx_login_context_user_seen ON auth.login_context_history (user_id, seen_at DESC);
CREATE INDEX login_context_history_organization_id_idx ON auth.login_context_history (organization_id);

-- internal/access/authentication
CREATE TABLE auth.login_sessions (
    token_hash    TEXT PRIMARY KEY,
    user_id       UUID NOT NULL, -- account.users (0010)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    ip            INET,
    user_agent    TEXT,
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    second_factor TEXT,
    CONSTRAINT login_sessions_second_factor_check CHECK (second_factor IN (
            'mfa', 'passkey', 'trusted_device', 'step_up'))
);
CREATE INDEX login_sessions_expires_at_idx ON auth.login_sessions (expires_at);
CREATE UNIQUE INDEX login_sessions_id_key ON auth.login_sessions (id);
CREATE INDEX login_sessions_user_id_idx ON auth.login_sessions (user_id);

-- internal/access/authentication
CREATE TABLE auth.login_source_failures (
    network        TEXT NOT NULL,
    email          TEXT NOT NULL,
    last_failed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (network, email)
);

-- internal/access/authentication
CREATE TABLE auth.login_source_throttles (
    network           TEXT PRIMARY KEY,
    throttled_at      TIMESTAMPTZ NOT NULL,
    throttled_until   TIMESTAMPTZ NOT NULL,
    distinct_accounts INTEGER NOT NULL
);

-- internal/access/recovery
CREATE TABLE auth.magic_links (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID, -- organization.organizations (0010)
    email           TEXT NOT NULL,
    token_hash      TEXT NOT NULL UNIQUE,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    app             TEXT NOT NULL DEFAULT 'console',
    return_to       TEXT,
    CONSTRAINT magic_links_app_check CHECK (app IN ('console', 'hosted_login'))
);
CREATE INDEX idx_magic_email ON auth.magic_links (organization_id, lower(email));
CREATE INDEX idx_magic_links_expires ON auth.magic_links (expires_at) WHERE used_at IS NULL;

-- internal/access/mfa
CREATE TABLE auth.mfa_attempt_budgets (
    user_id           UUID NOT NULL, -- account.users (0010)
    purpose           TEXT NOT NULL,
    failed_attempts   SMALLINT NOT NULL DEFAULT 0,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until      TIMESTAMPTZ,
    PRIMARY KEY (user_id, purpose),
    CONSTRAINT mfa_attempt_budgets_failed_attempts_check CHECK (failed_attempts >= 0 AND failed_attempts <= 5),
    CONSTRAINT mfa_attempt_budgets_purpose_check CHECK (length(purpose) >= 1 AND length(purpose) <= 128)
);
CREATE INDEX mfa_attempt_budgets_locked ON auth.mfa_attempt_budgets (locked_until)
    WHERE locked_until IS NOT NULL;

-- internal/access/authentication
CREATE TABLE auth.mfa_failure_streaks (
    user_id   UUID PRIMARY KEY, -- account.users (0010)
    failures  INTEGER NOT NULL DEFAULT 0,
    locked_at TIMESTAMPTZ,
    CONSTRAINT mfa_failure_streaks_failures_check CHECK (failures >= 0)
);

-- internal/access/authentication
CREATE TABLE auth.mfa_login_challenges (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID NOT NULL, -- account.users (0010)
    organization_id       UUID, -- organization.organizations (0010)
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claims                JSONB,
    failed_attempts       SMALLINT NOT NULL DEFAULT 0,
    passkey_session_id    UUID,
    push_challenge_id     UUID,
    codes_sent            INTEGER NOT NULL DEFAULT 0,
    enrollment            BOOLEAN NOT NULL DEFAULT FALSE,
    enrollment_started    BOOLEAN NOT NULL DEFAULT FALSE,
    first_factor          TEXT NOT NULL DEFAULT 'password',
    risk_email            BOOLEAN NOT NULL DEFAULT FALSE,
    email_code_hash       TEXT,
    email_code_expires_at TIMESTAMPTZ,
    email_code_sent_at    TIMESTAMPTZ,
    CONSTRAINT mfa_login_challenges_failed_attempts_check CHECK (
        failed_attempts >= 0
        AND failed_attempts <= 5),
    CONSTRAINT mfa_login_challenges_first_factor_check CHECK (first_factor IN (
            'password', 'magic_link', 'social', 'ldap'))
);
CREATE INDEX idx_mfa_login_chal_user ON auth.mfa_login_challenges (user_id);
CREATE INDEX mfa_login_challenges_organization_id_idx ON auth.mfa_login_challenges (organization_id);

-- internal/access/mfa
CREATE TABLE auth.mfa_otp_factors (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL, -- account.users (0010)
    channel     TEXT NOT NULL,
    destination TEXT NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, channel, destination),
    CONSTRAINT mfa_otp_factors_channel_check CHECK (channel IN ('email', 'sms'))
);

-- internal/access/mfa
CREATE TABLE auth.mfa_otp_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    factor_id  UUID NOT NULL REFERENCES auth.mfa_otp_factors (id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    purpose    TEXT NOT NULL,
    CONSTRAINT mfa_otp_codes_purpose_check CHECK (purpose IN ('sign_in', 'step_up', 'enrollment'))
);
CREATE INDEX idx_mfa_otp_codes_pending ON auth.mfa_otp_codes (factor_id) WHERE used_at IS NULL;

-- internal/access/mfa
CREATE TABLE auth.mfa_push_challenges (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL, -- account.users (0010)
    action       TEXT NOT NULL,
    context      JSONB NOT NULL DEFAULT '{}'::jsonb,
    status       TEXT NOT NULL DEFAULT 'pending',
    expires_at   TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '2 minutes',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at TIMESTAMPTZ,
    match_number SMALLINT,
    CONSTRAINT mfa_push_challenges_match_number_check CHECK (match_number >= 10 AND match_number <= 99),
    CONSTRAINT mfa_push_challenges_status_check CHECK (status IN ('pending', 'approved', 'denied', 'expired'))
);
CREATE INDEX mfa_push_challenges_user_status ON auth.mfa_push_challenges (user_id, status, expires_at);

-- internal/access/mfa
CREATE TABLE auth.mfa_push_devices (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID NOT NULL, -- account.users (0010)
    name                    TEXT NOT NULL DEFAULT '',
    platform                TEXT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    push_token_ct           BYTEA NOT NULL,
    push_token_nonce        BYTEA NOT NULL,
    push_token_hash         TEXT NOT NULL,
    device_token_hash       TEXT NOT NULL,
    encryption_version      SMALLINT NOT NULL DEFAULT 1,
    device_token_expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '180 days',
    CONSTRAINT mfa_push_devices_platform_check CHECK (platform IN ('ios', 'android')),
    CONSTRAINT mfa_push_secret_storage_valid CHECK (encryption_version = 1)
);
CREATE UNIQUE INDEX mfa_push_devices_user_token_hash ON auth.mfa_push_devices (user_id, push_token_hash);

-- internal/access/mfa
CREATE TABLE auth.mfa_push_pairings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL, -- account.users (0010)
    organization_id UUID, -- organization.organizations (0010)
    code_hash       TEXT NOT NULL UNIQUE,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    device_id       UUID REFERENCES auth.mfa_push_devices (id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX mfa_push_pairings_expires ON auth.mfa_push_pairings (expires_at);
CREATE INDEX mfa_push_pairings_user ON auth.mfa_push_pairings (user_id, created_at);
CREATE INDEX mfa_push_pairings_organization_id_idx ON auth.mfa_push_pairings (organization_id);

-- internal/access/mfa
CREATE TABLE auth.mfa_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL, -- account.users (0010)
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_mfa_recovery_user ON auth.mfa_recovery_codes (user_id);

-- internal/access/mfa
CREATE TABLE auth.mfa_totp (
    user_id              UUID PRIMARY KEY, -- account.users (0010)
    confirmed_at         TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    secret_ct            BYTEA NOT NULL,
    secret_nonce         BYTEA NOT NULL,
    encryption_version   SMALLINT NOT NULL DEFAULT 1,
    last_used_step       BIGINT,
    pending_secret_ct    BYTEA,
    pending_secret_nonce BYTEA,
    pending_started_at   TIMESTAMPTZ,
    CONSTRAINT mfa_totp_pending_complete CHECK (
        (pending_secret_ct IS NULL AND pending_secret_nonce IS NULL AND pending_started_at IS NULL)
        OR (pending_secret_ct IS NOT NULL AND pending_secret_nonce IS NOT NULL AND pending_started_at IS NOT NULL)),
    CONSTRAINT mfa_totp_secret_storage_valid CHECK (encryption_version = 1)
);

-- internal/operations/notifications
CREATE TABLE auth.notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL, -- account.users (0010)
    organization_id UUID, -- organization.organizations (0010)
    kind            TEXT NOT NULL DEFAULT 'info',
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    href            TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    read_at         TIMESTAMPTZ
);
CREATE INDEX idx_notifications_user_created ON auth.notifications (user_id, created_at DESC);
CREATE INDEX notifications_organization_id_idx ON auth.notifications (organization_id);

-- internal/federation/oidcsso, internal/federation/social
-- What a sign-in through an identity provider keeps between sending the
-- browser there and its return, read and deleted in one step by the state's
-- hash. kind names the flow that started it.
CREATE TABLE auth.oauth_states (
    state_hash      TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    organization_id UUID, -- organization.organizations (0010)
    connection_id   UUID,
    provider        TEXT,
    code_verifier   TEXT NOT NULL,
    nonce_hash      TEXT,
    redirect_uri    TEXT NOT NULL,
    return_to       TEXT,
    link_user_id    UUID,
    allow_create    BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oauth_states_kind_check CHECK (
        (kind = 'social' AND organization_id IS NOT NULL AND provider IS NOT NULL AND connection_id IS NULL
            AND link_user_id IS NULL AND NOT allow_create)
        OR (kind = 'oidc_connection' AND organization_id IS NOT NULL AND connection_id IS NOT NULL AND provider IS NULL
            AND nonce_hash IS NOT NULL AND link_user_id IS NULL AND NOT allow_create)
        OR (kind = 'platform_social' AND organization_id IS NULL AND provider IS NOT NULL AND connection_id IS NULL
            AND return_to IS NULL))
);
CREATE INDEX oauth_states_expires_at_idx ON auth.oauth_states (expires_at);
CREATE INDEX oauth_states_organization_id_idx ON auth.oauth_states (organization_id);

-- internal/federation/oidc
CREATE TABLE auth.oidc_authorization_codes (
    code_hash             TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    user_id               UUID NOT NULL,
    organization_id       UUID NOT NULL, -- organization.organizations (0010)
    redirect_uri          TEXT NOT NULL,
    scopes                TEXT[] NOT NULL,
    nonce                 TEXT,
    code_challenge        TEXT,
    code_challenge_method TEXT,
    expires_at            TIMESTAMPTZ NOT NULL,
    used_at               TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    login_session_id      UUID,
    resource              TEXT,
    auth_time             TIMESTAMPTZ,
    CONSTRAINT oidc_authorization_codes_code_challenge_method_check CHECK (code_challenge_method IN ('S256'))
);
CREATE INDEX idx_oidc_codes_login_session_unused ON auth.oidc_authorization_codes (login_session_id)
    WHERE login_session_id IS NOT NULL AND used_at IS NULL;
CREATE INDEX oidc_authorization_codes_organization_id_idx ON auth.oidc_authorization_codes (organization_id);

-- internal/federation/oidc
CREATE TABLE auth.oidc_ciba_requests (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_req_id_hash TEXT NOT NULL UNIQUE,
    client_id        TEXT NOT NULL,
    organization_id  UUID NOT NULL, -- organization.organizations (0010)
    user_id          UUID NOT NULL, -- account.users (0010)
    scopes           TEXT[] NOT NULL DEFAULT '{}'::text[],
    binding_message  TEXT,
    status           TEXT NOT NULL DEFAULT 'pending',
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_polled_at   TIMESTAMPTZ,
    consumed_at      TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ NOT NULL,
    approved_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oidc_ciba_requests_status_check CHECK (status IN ('pending', 'authorized', 'denied'))
);
CREATE INDEX idx_ciba_organization ON auth.oidc_ciba_requests (organization_id);
CREATE INDEX idx_ciba_user_pending ON auth.oidc_ciba_requests (user_id) WHERE status = 'pending';

-- internal/federation/oidc
CREATE TABLE auth.oidc_clients (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID NOT NULL, -- organization.organizations (0010)
    client_id               TEXT NOT NULL UNIQUE,
    client_secret_hash      TEXT,
    type                    TEXT NOT NULL DEFAULT 'confidential',
    name                    TEXT NOT NULL,
    redirect_uris           TEXT[] NOT NULL DEFAULT '{}'::text[],
    post_logout_uris        TEXT[] NOT NULL DEFAULT '{}'::text[],
    grant_types             TEXT[] NOT NULL DEFAULT '{authorization_code,refresh_token}'::text[],
    scopes                  TEXT[] NOT NULL DEFAULT '{openid,profile,email}'::text[],
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at             TIMESTAMPTZ,
    reviewed_by             UUID, -- account.users (0010)
    pkce_exempt_until       TIMESTAMPTZ,
    backchannel_logout_uri  TEXT,
    frontchannel_logout_uri TEXT,
    logo_uri                TEXT,
    client_uri              TEXT,
    web_origins             TEXT[],
    created_by              UUID,
    CONSTRAINT oidc_clients_client_uri_check CHECK (
        client_uri IS NULL
        OR (client_uri ~~ 'https://%' AND length(client_uri) <= 2048)),
    CONSTRAINT oidc_clients_logo_uri_check CHECK (
        logo_uri IS NULL
        OR (logo_uri ~~ 'https://%' AND length(logo_uri) <= 2048)),
    CONSTRAINT oidc_clients_type_check CHECK (type IN ('confidential', 'public'))
);
CREATE INDEX oidc_clients_organization_id_idx ON auth.oidc_clients (organization_id);

-- internal/federation/oidc
CREATE TABLE auth.oidc_client_auth_lockouts (
    client_row_id     UUID NOT NULL REFERENCES auth.oidc_clients (id) ON DELETE CASCADE,
    failures          INTEGER NOT NULL DEFAULT 0,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_failure_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until      TIMESTAMPTZ,
    source_network    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (client_row_id, source_network)
);

-- internal/federation/oidc
CREATE TABLE auth.oidc_consent_requests (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    login_session_id      UUID NOT NULL REFERENCES auth.login_sessions (id) ON DELETE CASCADE,
    user_id               UUID NOT NULL, -- account.users (0010)
    client_id             TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scopes                TEXT[] NOT NULL DEFAULT '{}'::text[],
    state                 TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at            TIMESTAMPTZ NOT NULL,
    used_at               TIMESTAMPTZ,
    resource              TEXT NOT NULL DEFAULT '',
    CONSTRAINT oidc_consent_requests_code_challenge_method_check CHECK (code_challenge_method IN ('', 'S256'))
);
CREATE INDEX idx_oidc_consent_requests_expires ON auth.oidc_consent_requests (expires_at);
CREATE INDEX idx_oidc_consent_requests_login_session ON auth.oidc_consent_requests (login_session_id);

-- internal/federation/oidc
CREATE TABLE auth.oidc_consents (
    user_id    UUID NOT NULL, -- account.users (0010)
    client_id  TEXT NOT NULL,
    scopes     TEXT[] NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, client_id)
);

-- internal/federation/oidc
CREATE TABLE auth.oidc_device_codes (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash TEXT NOT NULL UNIQUE,
    user_code        TEXT NOT NULL UNIQUE,
    client_id        TEXT NOT NULL,
    organization_id  UUID NOT NULL, -- organization.organizations (0010)
    user_id          UUID, -- account.users (0010)
    scopes           TEXT[] NOT NULL DEFAULT '{}'::text[],
    status           TEXT NOT NULL DEFAULT 'pending',
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_polled_at   TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ NOT NULL,
    approved_at      TIMESTAMPTZ,
    consumed_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oidc_device_codes_status_check CHECK (status IN ('pending', 'authorized', 'denied'))
);
CREATE INDEX oidc_device_codes_expires_at_idx ON auth.oidc_device_codes (expires_at);
CREATE INDEX oidc_device_codes_organization_id_idx ON auth.oidc_device_codes (organization_id);

-- internal/federation/oidc
CREATE TABLE auth.oidc_logout_deliveries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL, -- organization.organizations (0010)
    client_id       TEXT NOT NULL,
    uri             TEXT NOT NULL,
    logout_token    TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at    TIMESTAMPTZ,
    failed_at       TIMESTAMPTZ,
    last_error      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_oidc_logout_deliveries_due ON auth.oidc_logout_deliveries (next_attempt_at)
    WHERE delivered_at IS NULL AND failed_at IS NULL;
CREATE INDEX oidc_logout_deliveries_organization_id_idx ON auth.oidc_logout_deliveries (organization_id);

-- internal/federation/oidc
CREATE TABLE auth.oidc_refresh_tokens (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash              TEXT NOT NULL UNIQUE,
    client_id               TEXT NOT NULL,
    user_id                 UUID NOT NULL, -- account.users (0010)
    organization_id         UUID NOT NULL, -- organization.organizations (0010)
    scopes                  TEXT[] NOT NULL DEFAULT '{}'::text[],
    issued_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ NOT NULL,
    used_at                 TIMESTAMPTZ,
    replaced_by             UUID,
    revoked_at              TIMESTAMPTZ,
    resource                TEXT,
    login_session_id        UUID,
    grant_expires_at        TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days',
    authorization_code_hash TEXT,
    grant_id                UUID,
    auth_time               TIMESTAMPTZ,
    UNIQUE (organization_id, id),
    CONSTRAINT oidc_refresh_tokens_replaced_by_fkey FOREIGN KEY (organization_id, replaced_by)
        REFERENCES auth.oidc_refresh_tokens (organization_id, id)
);
CREATE INDEX idx_oidc_refresh_client_user ON auth.oidc_refresh_tokens (client_id, user_id);
CREATE INDEX idx_oidc_refresh_login_session_unrevoked ON auth.oidc_refresh_tokens (login_session_id)
    WHERE login_session_id IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX idx_oidc_refresh_tokens_code ON auth.oidc_refresh_tokens (client_id, authorization_code_hash)
    WHERE authorization_code_hash IS NOT NULL;
CREATE INDEX idx_oidc_refresh_tokens_grant ON auth.oidc_refresh_tokens (grant_id);
CREATE INDEX idx_oidc_refresh_user_unrevoked ON auth.oidc_refresh_tokens (user_id) WHERE revoked_at IS NULL;

-- internal/federation/oidc
CREATE TABLE auth.oidc_resources (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL, -- organization.organizations (0010)
    identifier       TEXT NOT NULL,
    name             TEXT NOT NULL DEFAULT '',
    server_client_id TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, identifier)
);
CREATE UNIQUE INDEX uq_oidc_resources_identifier ON auth.oidc_resources (identifier);

-- internal/access/passkeys
CREATE TABLE auth.passkey_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL, -- account.users (0010)
    credential_id   BYTEA NOT NULL,
    public_key      BYTEA NOT NULL,
    sign_count      BIGINT NOT NULL DEFAULT 0,
    aaguid          UUID,
    transports      TEXT[],
    name            TEXT,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX idx_passkey_user ON auth.passkey_credentials (user_id);
CREATE UNIQUE INDEX uq_passkey_credid ON auth.passkey_credentials (credential_id);

-- internal/access/authentication
CREATE TABLE auth.password_credentials (
    user_id       UUID PRIMARY KEY, -- account.users (0010)
    password_hash TEXT NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- internal/access/recovery
CREATE TABLE auth.password_resets (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL, -- account.users (0010)
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_password_resets_expires ON auth.password_resets (expires_at) WHERE used_at IS NULL;
CREATE INDEX idx_password_resets_user ON auth.password_resets (user_id);

-- internal/federation/social
CREATE TABLE auth.platform_social_identities (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id   UUID NOT NULL, -- account.users (0010)
    provider  TEXT NOT NULL,
    subject   TEXT NOT NULL,
    email     TEXT,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, subject)
);
CREATE INDEX idx_platform_social_identities_user ON auth.platform_social_identities (user_id);

-- internal/federation/social
CREATE TABLE auth.platform_social_link_codes (
    code_hash  TEXT PRIMARY KEY,
    user_id    UUID NOT NULL, -- account.users (0010)
    provider   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    email      TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- internal/access/authorization/rebac
-- organization_id's key doesn't cascade: the organization purge deletes the tuples
-- in batches first.
CREATE TABLE auth.relation_tuples (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL, -- organization.organizations (0010)
    object_type      TEXT NOT NULL,
    object_id        TEXT NOT NULL,
    relation         TEXT NOT NULL,
    subject_type     TEXT NOT NULL,
    subject_id       TEXT NOT NULL,
    subject_relation TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_relation_tuple_subject ON auth.relation_tuples (organization_id, subject_type, subject_id);
CREATE UNIQUE INDEX uq_relation_tuple
    ON auth.relation_tuples (organization_id, object_type, object_id, relation, subject_type, subject_id, subject_relation);

-- internal/access/threat/risk
CREATE TABLE auth.risk_settings (
    organization_id           UUID PRIMARY KEY, -- organization.organizations (0010)
    medium_threshold          DOUBLE PRECISION NOT NULL DEFAULT 0.50,
    high_threshold            DOUBLE PRECISION NOT NULL DEFAULT 0.80,
    force_mfa_at_level        TEXT NOT NULL DEFAULT 'high',
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    impossible_travel_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    min_travel_hours          DOUBLE PRECISION NOT NULL DEFAULT 3,
    device_reputation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT risk_settings_force_mfa_at_level_check CHECK (force_mfa_at_level IN ('medium', 'high')),
    CONSTRAINT risk_settings_high_threshold_check CHECK (
        high_threshold >= (0.1)::double precision
        AND high_threshold <= (1.0)::double precision),
    CONSTRAINT risk_settings_medium_threshold_check CHECK (
        medium_threshold >= (0.1)::double precision
        AND medium_threshold <= (1.0)::double precision)
);

-- internal/federation/saml
CREATE TABLE auth.saml_authn_requests (
    request_id    TEXT PRIMARY KEY,
    connection_id UUID NOT NULL, -- organization.saml_connections (0010)
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    return_to     TEXT
);
CREATE INDEX saml_authn_requests_expiry ON auth.saml_authn_requests (expires_at);

-- internal/federation/saml
CREATE TABLE auth.saml_replay_ids (
    connection_id UUID NOT NULL, -- organization.saml_connections (0010)
    kind          TEXT NOT NULL,
    saml_id       TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (connection_id, kind, saml_id),
    CONSTRAINT saml_replay_ids_kind_check CHECK (kind IN ('response', 'assertion'))
);
CREATE INDEX saml_replay_ids_expiry ON auth.saml_replay_ids (expires_at);

-- internal/federation/saml
CREATE TABLE auth.saml_test_sign_ins (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id UUID NOT NULL, -- organization.saml_connections (0010)
    request_id    TEXT NOT NULL UNIQUE,
    return_url    TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    result        JSONB,
    expires_at    TIMESTAMPTZ NOT NULL,
    completed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT saml_test_sign_ins_status_check CHECK (status IN ('pending', 'succeeded', 'failed'))
);
CREATE INDEX saml_test_sign_ins_connection ON auth.saml_test_sign_ins (connection_id);
CREATE INDEX saml_test_sign_ins_created ON auth.saml_test_sign_ins (created_at);

-- internal/access/threat/threat
-- An append-only log: organization_id has no foreign key, so recording never locks
-- the organization's row. The organization purge deletes its rows in batches.
CREATE TABLE auth.security_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    user_id         UUID,
    type            TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'low',
    detail          TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open',
    ip              INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    resolved_by     UUID
);
CREATE INDEX idx_security_events_organization_created ON auth.security_events (organization_id, created_at DESC);

-- internal/developer/principal
CREATE TABLE auth.service_principals (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id            UUID NOT NULL, -- organization.organizations (0010)
    name                       TEXT NOT NULL,
    description                TEXT NOT NULL DEFAULT '',
    secret_hash                TEXT NOT NULL,
    scopes                     TEXT[] NOT NULL DEFAULT '{}'::text[],
    disabled_at                TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at               TIMESTAMPTZ,
    previous_secret_hash       TEXT,
    previous_secret_expires_at TIMESTAMPTZ,
    created_by                 UUID
);
CREATE UNIQUE INDEX uq_service_principals_organization_name ON auth.service_principals (organization_id, lower(name));

-- internal/access/authentication
-- organization_id's key doesn't cascade: the organization purge deletes the
-- sessions in batches first.
CREATE TABLE auth.sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL, -- account.users (0010)
    organization_id UUID, -- organization.organizations (0010)
    ip              INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,
    superseded_by   UUID REFERENCES auth.sessions (id) ON DELETE SET NULL,
    hook_claims     JSONB,
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days',
    idle_timeout    INTERVAL NOT NULL DEFAULT INTERVAL '24 hours',
    country         TEXT,
    second_factor   TEXT,
    signed_in_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    city            TEXT,
    CONSTRAINT sessions_city_check CHECK (char_length(city) >= 1 AND char_length(city) <= 100),
    CONSTRAINT sessions_country_check CHECK (country ~ '^[A-Z]{2}$'),
    CONSTRAINT sessions_second_factor_check CHECK (second_factor IN (
            'mfa', 'passkey', 'trusted_device', 'step_up'))
);
CREATE INDEX idx_sessions_active ON auth.sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_organization_active ON auth.sessions (organization_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_user ON auth.sessions (user_id);

-- internal/access/mfa
CREATE TABLE auth.mfa_verifications (
    user_id     UUID NOT NULL, -- account.users (0010)
    method      TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_id  UUID PRIMARY KEY REFERENCES auth.sessions (id) ON DELETE CASCADE
);
CREATE INDEX idx_mfa_verifications_user ON auth.mfa_verifications (user_id);

-- internal/access/authentication
CREATE TABLE auth.refresh_tokens (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id        UUID NOT NULL REFERENCES auth.sessions (id) ON DELETE CASCADE,
    token_hash        TEXT NOT NULL UNIQUE,
    issued_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,
    used_at           TIMESTAMPTZ,
    replaced_by       UUID REFERENCES auth.refresh_tokens (id),
    replacement_enc   BYTEA,
    replacement_nonce BYTEA
);
CREATE INDEX idx_refresh_session ON auth.refresh_tokens (session_id);
CREATE INDEX idx_refresh_tokens_replacement ON auth.refresh_tokens (used_at)
    WHERE replacement_enc IS NOT NULL;

-- internal/access/authentication
CREATE TABLE auth.trusted_devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL, -- account.users (0010)
    organization_id UUID, -- organization.organizations (0010)
    token_hash      TEXT NOT NULL UNIQUE,
    label           TEXT NOT NULL DEFAULT '',
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX idx_trusted_devices_organization ON auth.trusted_devices (organization_id, expires_at);
CREATE INDEX idx_trusted_devices_user ON auth.trusted_devices (user_id);

-- internal/access/passkeys
CREATE TABLE auth.webauthn_sessions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID, -- account.users (0010)
    kind                    TEXT NOT NULL,
    data                    JSONB NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    subject_id              UUID,
    pending_email           TEXT,
    pending_display_name    TEXT,
    pending_organization_id UUID, -- organization.organizations (0010)
    pending_invite_id       UUID -- organization.invites (0010)
);
