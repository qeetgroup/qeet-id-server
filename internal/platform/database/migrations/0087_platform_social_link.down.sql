ALTER TABLE auth.platform_social_states DROP COLUMN IF EXISTS link_user_id;
DROP TABLE IF EXISTS auth.platform_social_identities;
