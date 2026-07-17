-- Queries for the branding domain.
-- Static queries against tenant.branding live here and are compiled by sqlc into ./dbgen.
-- The Upsert query uses a COALESCE/NULLIF expression that sqlc cannot parse reliably;
-- it intentionally remains hand-written in branding.go.

-- name: GetBranding :one
SELECT tenant_id, logo_url, primary_color, secondary_color,
       custom_domain, email_from_name, email_from_address, settings
FROM tenant.branding WHERE tenant_id = $1;
