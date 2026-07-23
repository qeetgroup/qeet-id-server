-- 0051_self_registration — per-tenant gate for hosted B2C self-signup; off by default so B2B tenants stay invite-only unless they opt in
ALTER TABLE tenant.auth_policy
    ADD COLUMN self_registration_enabled BOOLEAN NOT NULL DEFAULT false;
