-- 0040_magic_link_ttl — configurable magic-link lifetime on tenant.auth_policy
ALTER TABLE tenant.auth_policy
    ADD COLUMN IF NOT EXISTS magic_link_ttl_minutes INT NOT NULL DEFAULT 60
        CHECK (magic_link_ttl_minutes BETWEEN 5 AND 1440);
