-- Per-tenant gate for hosted end-user self-registration (B2C CIAM signup).
-- Off by default: a tenant must explicitly opt in before the public /signup
-- page and POST /v1/auth/register will create users in that tenant. This keeps
-- workforce/B2B tenants invite-only unless they choose otherwise.
ALTER TABLE tenant.auth_policy
    ADD COLUMN self_registration_enabled BOOLEAN NOT NULL DEFAULT false;
