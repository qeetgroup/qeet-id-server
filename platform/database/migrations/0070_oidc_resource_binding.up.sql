-- RFC 8707 resource-indicator binding was only applied on the initial
-- authorization_code exchange; a refreshed access token silently dropped
-- the audience restriction. Persist the bound resource on the refresh token
-- itself so rotation can re-bind the same (or an explicitly overridden)
-- resource on the reissued access token.
ALTER TABLE auth.oidc_refresh_tokens ADD COLUMN IF NOT EXISTS resource TEXT;
