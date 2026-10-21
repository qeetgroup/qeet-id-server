-- Drops the key only; rows removed by the up migration named no account and are not restored.
ALTER TABLE tenant.group_members DROP CONSTRAINT IF EXISTS group_members_user_id_fkey;
