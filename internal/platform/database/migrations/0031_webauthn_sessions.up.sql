-- 0031_webauthn_sessions — in-flight WebAuthn ceremony state (/begin → /finish, single-use).
-- user_id is NULL for discoverable (usernameless) login, where the user is known only after the authenticator responds.
CREATE TABLE auth.webauthn_sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID REFERENCES "user".users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,        -- 'register' | 'login' | 'login_discoverable'
    data       JSONB NOT NULL,       -- marshaled webauthn.SessionData
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
