ALTER TABLE auth.oidc_clients DROP COLUMN IF EXISTS reviewed_by;
ALTER TABLE auth.oidc_clients DROP COLUMN IF EXISTS reviewed_at;
