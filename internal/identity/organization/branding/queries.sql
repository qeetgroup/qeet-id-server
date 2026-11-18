-- Queries for the branding domain, against organization.branding.

-- name: GetBranding :one
SELECT organization_id, logo_url, primary_color, secondary_color,
       custom_domain, email_from_name, email_from_address, settings
FROM organization.branding WHERE organization_id = $1;

-- UpsertBranding stores an organization's branding; a JSON null settings is
-- stored as {}. email_from_address is no longer kept.
-- name: UpsertBranding :exec
INSERT INTO organization.branding (
    organization_id, logo_url, primary_color, secondary_color, custom_domain,
    email_from_name, email_from_address, settings
) VALUES (
    @organization_id, @logo_url, @primary_color, @secondary_color, @custom_domain,
    @email_from_name, NULL, COALESCE(NULLIF(@settings::jsonb, 'null'::jsonb), '{}'::jsonb)
)
ON CONFLICT (organization_id) DO UPDATE SET
    logo_url = EXCLUDED.logo_url,
    primary_color = EXCLUDED.primary_color,
    secondary_color = EXCLUDED.secondary_color,
    custom_domain = EXCLUDED.custom_domain,
    email_from_name = EXCLUDED.email_from_name,
    email_from_address = EXCLUDED.email_from_address,
    settings = EXCLUDED.settings,
    updated_at = NOW();
