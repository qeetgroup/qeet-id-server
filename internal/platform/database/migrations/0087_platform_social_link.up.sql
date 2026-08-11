-- Tenant-less connected social accounts for platform (console) users.
-- "user".external_identities is tenant-scoped (tenant_id NOT NULL, FK to
-- tenant.tenants), so it can't hold a console account's social identity before
-- (or without) an organization. Platform sign-in and the authenticated link
-- flow record identities here instead.
CREATE TABLE auth.platform_social_identities (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    email      TEXT,
    linked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One provider identity maps to exactly one Qeet user: prevents linking the
    -- same Google/GitHub account to two different accounts.
    UNIQUE (provider, subject)
);

CREATE INDEX idx_platform_social_identities_user
    ON auth.platform_social_identities (user_id);

-- An authenticated "link" ceremony stashes the initiating user here so the OAuth
-- callback attaches the identity to that user instead of logging in / creating a
-- new account. NULL = an ordinary (login/signup) social ceremony.
ALTER TABLE auth.platform_social_states ADD COLUMN link_user_id UUID;
