ALTER TABLE tenant.admin_portal_links
    ADD COLUMN redeemed_at TIMESTAMPTZ;

-- Every row predates fragment-only links and may have exposed its credential
-- through browser or proxy path logs. Require administrators to issue a new
-- link after this migration rather than carrying that risk into the session
-- exchange model.
UPDATE tenant.admin_portal_links
SET revoked_at = COALESCE(revoked_at, NOW());

CREATE TABLE auth.admin_portal_sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    link_id      UUID        NOT NULL REFERENCES tenant.admin_portal_links(id) ON DELETE CASCADE,
    token_hash   TEXT        NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX admin_portal_sessions_link
    ON auth.admin_portal_sessions (link_id);
CREATE INDEX admin_portal_sessions_expiry
    ON auth.admin_portal_sessions (expires_at)
    WHERE revoked_at IS NULL;
