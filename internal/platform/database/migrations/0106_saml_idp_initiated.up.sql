-- 0106_saml_idp_initiated re-admits IdP-initiated SSO as an explicit per-
-- connection opt-in.
--
-- 0099 began consuming the SP-initiated AuthnRequest as part of replay
-- protection, which made a response with no InResponseTo unverifiable and so
-- silently dropped support for IdP-initiated login (the "launch this app from
-- your Okta/Entra dashboard" flow). That is the right default — an
-- unsolicited assertion cannot be correlated to a request this SP made — but
-- it is a capability plenty of enterprise IdPs rely on.
--
-- Opting in relaxes only the request correlation. Signature, issuer, audience,
-- destination, and time-condition validation are unchanged, and the response
-- and assertion IDs are still consumed against auth.saml_replay_ids, so an
-- assertion still cannot be replayed within its validity window.

ALTER TABLE tenant.saml_connections
    ADD COLUMN allow_idp_initiated BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN tenant.saml_connections.allow_idp_initiated IS
    'Accept unsolicited assertions with no InResponseTo. Replay IDs are still enforced.';
