-- 0229_social_provider_adapters — an organisation's GitHub, Facebook, X,
-- Discord and Apple sign-in. Apple's client secret is a JWT the server signs
-- with the organisation's key, so its provider keeps the team and key ids (the
-- key itself is sealed as the client secret), and an Apple sign-in's state its
-- nonce.
ALTER TABLE tenant.social_providers
    ADD COLUMN IF NOT EXISTS apple_team_id TEXT,
    ADD COLUMN IF NOT EXISTS apple_key_id  TEXT;
ALTER TABLE auth.social_oauth_states ADD COLUMN IF NOT EXISTS nonce_hash TEXT;
