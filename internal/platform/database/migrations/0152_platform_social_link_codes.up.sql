-- 0152_platform_social_link_codes — connecting a provider to an account is
-- completed by that account.
--
-- The account page connects a provider by asking for a link, sending the
-- browser to the provider, and attaching whatever the provider returned at the
-- callback to the account the link was asked for. The callback trusted whoever
-- arrived: a connect link sent to someone else attached their provider account
-- to the sender's, who then held a way into the account they would land in.
-- The callback now holds what the provider returned here, under a one-time
-- code, and the account page attaches it only for the account that asked.
CREATE TABLE auth.platform_social_link_codes (
    code_hash  TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    email      TEXT, -- only an address the provider verified
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
