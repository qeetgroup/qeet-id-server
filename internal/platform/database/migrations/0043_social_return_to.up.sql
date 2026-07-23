-- 0043_social_return_to — carry the hosted OAuth authorize URL through the social round-trip
-- (set the SSO cookie + bounce to /oauth/authorize on callback); empty for the SPA one-time-code flow.
ALTER TABLE auth.social_oauth_states ADD COLUMN return_to TEXT NOT NULL DEFAULT '';
