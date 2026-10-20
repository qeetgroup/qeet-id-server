-- 0141_pkce_every_client — every application proves its sign-ins with PKCE.
--
-- pkce_exempt_until lets an organisation keep a confidential application that
-- doesn't send a proof key (or a nonce) working until a date, while it is
-- updated; NULL (every application, including existing ones) means no
-- exemption. Existing applications get none: there are no live integrations
-- to keep, and an exemption is an admin's deliberate, dated choice.
ALTER TABLE auth.oidc_clients ADD COLUMN pkce_exempt_until TIMESTAMPTZ;

-- authorization_code_hash is the code a grant was redeemed from, carried along
-- its rotations, so a second redemption of that code can revoke what the first
-- one issued (RFC 6749 §4.1.2). NULL for grants from before this column and
-- for those that didn't come from a code.
ALTER TABLE auth.oidc_refresh_tokens ADD COLUMN authorization_code_hash TEXT;
CREATE INDEX idx_oidc_refresh_tokens_code
    ON auth.oidc_refresh_tokens (client_id, authorization_code_hash)
    WHERE authorization_code_hash IS NOT NULL;
