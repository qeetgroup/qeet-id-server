-- Shadow-AI discovery: an OIDC client that picked up a machine grant type
-- (client_credentials or token-exchange) is capable of unattended access the
-- same way an agent or service account is, but — unlike those two registries
-- — nothing forces it through an explicit review. reviewed_at/reviewed_by let
-- an admin acknowledge one and have it drop off the "needs review" list.
ALTER TABLE auth.oidc_clients ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
ALTER TABLE auth.oidc_clients ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES "user".users(id);
