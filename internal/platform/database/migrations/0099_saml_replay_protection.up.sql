CREATE TABLE auth.saml_authn_requests (
    request_id     TEXT PRIMARY KEY,
    connection_id UUID        NOT NULL REFERENCES tenant.saml_connections(id) ON DELETE CASCADE,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX saml_authn_requests_expiry
    ON auth.saml_authn_requests (expires_at);

CREATE TABLE auth.saml_replay_ids (
    connection_id UUID        NOT NULL REFERENCES tenant.saml_connections(id) ON DELETE CASCADE,
    kind          TEXT        NOT NULL CHECK (kind IN ('response', 'assertion')),
    saml_id       TEXT        NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (connection_id, kind, saml_id)
);

CREATE INDEX saml_replay_ids_expiry
    ON auth.saml_replay_ids (expires_at);
