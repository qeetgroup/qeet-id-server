-- 0138_oidc_consent_requests — an authorization request waiting on the hosted
-- consent screen, kept by the server.
--
-- The consent screen used to receive the whole authorize query and post it back
-- with the decision, so every protocol value, including the redirect_uri a
-- denial was sent to, came from the browser. The authorize endpoint now checks
-- the request, stores it here and hands the screen only the row's id; the
-- decision names that id and nothing else. A request belongs to the hosted-login
-- session that started it (ending the session removes it), can be decided once
-- (used_at), and lapses at expires_at.
CREATE TABLE auth.oidc_consent_requests (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    login_session_id      UUID NOT NULL REFERENCES auth.login_sessions (id) ON DELETE CASCADE,
    user_id               UUID NOT NULL REFERENCES "user".users (id) ON DELETE CASCADE,
    client_id             TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scopes                TEXT[] NOT NULL DEFAULT '{}',
    state                 TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at            TIMESTAMPTZ NOT NULL,
    used_at               TIMESTAMPTZ
);

CREATE INDEX idx_oidc_consent_requests_login_session ON auth.oidc_consent_requests (login_session_id);
CREATE INDEX idx_oidc_consent_requests_expires ON auth.oidc_consent_requests (expires_at);
