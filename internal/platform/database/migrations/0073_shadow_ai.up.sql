-- 0073_shadow_ai — flag OIDC clients with a machine grant (client_credentials / token-exchange) for review:
-- like agents/service-accounts they allow unattended access, but nothing forces a review; reviewed_at/reviewed_by clear them off the "needs review" list.
ALTER TABLE auth.oidc_clients ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
ALTER TABLE auth.oidc_clients ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES "user".users(id);
