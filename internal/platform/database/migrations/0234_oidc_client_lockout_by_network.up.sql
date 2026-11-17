-- 0234_oidc_client_lockout_by_network — an application's wrong secrets are
-- counted, and lock it out, per source network.
--
-- A client_id is public, so counting wrong secrets per application let anyone
-- who knew one lock the application out for all its users. Each row now counts
-- the wrong secrets from one source network (an IPv4 address or an IPv6 /64;
-- '' when the address is unknown), and its lockout refuses that network only.
-- The rows there carry on as the unknown network's.
ALTER TABLE auth.oidc_client_auth_lockouts
    DROP CONSTRAINT oidc_client_auth_lockouts_pkey,
    ADD COLUMN source_network TEXT NOT NULL DEFAULT '';
