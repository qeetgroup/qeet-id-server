-- 0095_tenant_logo — a first-class organization logo/avatar (free identity field,
-- distinct from the paid hosted-login branding logo). Stored as a URL or a small
-- inline data URL; empty means "use the initials avatar" in the UI.
ALTER TABLE tenant.tenants ADD COLUMN logo_url TEXT NOT NULL DEFAULT '';
