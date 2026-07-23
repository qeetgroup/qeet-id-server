-- 0070_oidc_resource_binding — persist the RFC 8707 resource on the refresh token so rotation re-binds the audience (a refresh previously dropped the resource restriction)
ALTER TABLE auth.oidc_refresh_tokens ADD COLUMN IF NOT EXISTS resource TEXT;
