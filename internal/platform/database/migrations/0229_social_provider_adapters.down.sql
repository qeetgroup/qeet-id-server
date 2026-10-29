ALTER TABLE auth.social_oauth_states DROP COLUMN IF EXISTS nonce_hash;
ALTER TABLE tenant.social_providers DROP COLUMN IF EXISTS apple_key_id, DROP COLUMN IF EXISTS apple_team_id;
