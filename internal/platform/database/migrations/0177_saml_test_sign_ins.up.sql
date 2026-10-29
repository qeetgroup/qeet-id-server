-- 0177_saml_test_sign_ins — a test of a SAML connection: a real round trip
-- through the organisation's IdP whose answer is checked and reported, and
-- signs nobody in. Keyed by connection like the AuthnRequest and replay
-- tables; its AuthnRequest is recorded here only, so the sign-in path can
-- never accept the answer to one.
CREATE TABLE auth.saml_test_sign_ins (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id UUID        NOT NULL REFERENCES tenant.saml_connections(id) ON DELETE CASCADE,
    request_id    TEXT        NOT NULL UNIQUE,
    return_url    TEXT        NOT NULL,
    status        TEXT        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'succeeded', 'failed')),
    result        JSONB,
    expires_at    TIMESTAMPTZ NOT NULL,
    completed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX saml_test_sign_ins_connection ON auth.saml_test_sign_ins (connection_id);
CREATE INDEX saml_test_sign_ins_created ON auth.saml_test_sign_ins (created_at);
