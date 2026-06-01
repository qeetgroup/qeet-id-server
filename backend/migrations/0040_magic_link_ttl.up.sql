-- 0040: Magic-link lifetime, alongside the existing magic_link_enabled toggle in the
-- tenant auth policy. Consumed when issuing a passwordless sign-in link.
ALTER TABLE tenant.auth_policy
    ADD COLUMN IF NOT EXISTS magic_link_ttl_minutes INT NOT NULL DEFAULT 60
        CHECK (magic_link_ttl_minutes BETWEEN 5 AND 1440);
