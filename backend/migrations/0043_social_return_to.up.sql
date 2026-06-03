-- return_to carries the hosted OAuth authorize URL through the social login
-- round-trip, so after a successful provider callback we can set the SSO cookie
-- and bounce the browser back to /oauth/authorize. Empty for the SPA flow, which
-- trades a one-time code at /social/exchange instead.
ALTER TABLE auth.social_oauth_states ADD COLUMN return_to TEXT NOT NULL DEFAULT '';
