DROP TABLE IF EXISTS auth.admin_portal_sessions;

ALTER TABLE tenant.admin_portal_links
    DROP COLUMN IF EXISTS redeemed_at;
