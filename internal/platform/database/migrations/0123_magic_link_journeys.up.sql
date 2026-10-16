-- 0123_magic_link_journeys — a magic link returns to where it was asked for.
--
-- tenant_id becomes optional: a link asked for from the console's sign-in page
-- names no organisation (the account is found by its address, as password
-- sign-in finds it). app is where the link opens: 'console' (the console's
-- magic page, which signs in with tokens) or 'hosted_login' (the hosted login
-- page, which opens a hosted-login session and continues the sign-in journey
-- at return_to). A link is exchanged only by the app it was issued for.
ALTER TABLE auth.magic_links ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE auth.magic_links
    ADD COLUMN IF NOT EXISTS app TEXT NOT NULL DEFAULT 'console'
        CHECK (app IN ('console', 'hosted_login'));
ALTER TABLE auth.magic_links ADD COLUMN IF NOT EXISTS return_to TEXT;
