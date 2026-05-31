-- In-flight WebAuthn ceremony state. A /begin endpoint stores the challenge +
-- marshaled webauthn.SessionData; the matching /finish consumes it. Single-use
-- and short-lived. user_id is NULL for discoverable (usernameless) login, where
-- the user is only known once the authenticator reveals the credential.
CREATE TABLE auth.webauthn_sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID REFERENCES "user".users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,        -- 'register' | 'login' | 'login_discoverable'
    data       JSONB NOT NULL,       -- marshaled webauthn.SessionData
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
