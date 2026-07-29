-- 0085_platform_social — platform-level (tenant-less) social login for the
-- console's own Qeet ID accounts. The tenant-scoped social tables
-- (auth.social_oauth_states / auth.social_login_codes) require a tenant, but the
-- console sign-in has none (you sign up tenant-less, then create an org). So the
-- platform OAuth CSRF state + one-time login codes live here, tenant-less.
-- Providers (Google for now) are configured via env, not the per-tenant table.
CREATE TABLE auth.platform_social_states (
    state_hash    TEXT PRIMARY KEY,
    provider      TEXT NOT NULL,
    code_verifier TEXT NOT NULL, -- PKCE verifier
    redirect_uri  TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth.platform_social_codes (
    code_hash  TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    used_at    TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
