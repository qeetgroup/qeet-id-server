-- 0172_vault_connect_pkce — a connected account's code redeems only with the
-- verifier its ceremony began with (PKCE), so a code taken on its way back
-- is no use to anyone else.
ALTER TABLE tenant.token_vault_connect_states ADD COLUMN code_verifier TEXT;
