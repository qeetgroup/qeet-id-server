-- 0135_group_members_user_fk — a group member must be a real account.
--
-- tenant.group_members.user_id had no foreign key, so adding a member accepted
-- any UUID. Rows naming an id with no account are removed first, then the key is
-- added; deleting an account removes its group memberships with it.
DELETE FROM tenant.group_members gm
WHERE NOT EXISTS (SELECT 1 FROM "user".users u WHERE u.id = gm.user_id);

ALTER TABLE tenant.group_members
    ADD CONSTRAINT group_members_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES "user".users(id) ON DELETE CASCADE;
