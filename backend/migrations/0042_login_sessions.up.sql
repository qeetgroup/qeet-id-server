-- Hosted-login SSO sessions: proof that a browser is signed in to the Qeet ID
-- identity provider, used to drive the OAuth authorize/consent flow without
-- exposing tokens to JS. Distinct from API access/refresh tokens; the cookie
-- value is stored only as a hash, like refresh tokens.
CREATE TABLE auth.login_sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    ip          INET,
    user_agent  TEXT
);

CREATE INDEX login_sessions_user_id_idx    ON auth.login_sessions (user_id);
CREATE INDEX login_sessions_expires_at_idx ON auth.login_sessions (expires_at);
