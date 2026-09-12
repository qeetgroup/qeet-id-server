-- 0113_domain_settings — per-domain state the console's Domains screen shows.
--
-- Until now a domain was only "verified or not". The screen distinguishes three
-- states — verified, awaiting DNS, and needs attention — and the difference
-- between the last two is whether a verification attempt has actually failed.
-- That needs the attempt recorded, not just its success.
--
-- sso_enabled / jit_enabled are per-domain switches rather than a consequence of
-- verification: an org may verify a domain for ownership without wanting SSO
-- routing or just-in-time provisioning turned on for it.
ALTER TABLE tenant.domains
    ADD COLUMN IF NOT EXISTS last_checked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_error      TEXT,
    ADD COLUMN IF NOT EXISTS sso_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS jit_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS is_default      BOOLEAN NOT NULL DEFAULT FALSE;

-- At most one default domain per tenant. Partial, so the many non-default rows
-- don't collide with each other.
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_default_domain
    ON tenant.domains (tenant_id)
    WHERE is_default;
