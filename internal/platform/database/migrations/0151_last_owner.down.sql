DROP TRIGGER IF EXISTS keep_owner_on_account_delete ON "user".users;
DROP TRIGGER IF EXISTS keep_owner_on_account_change ON "user".users;
DROP TRIGGER IF EXISTS keep_owner_on_role_removal ON rbac.user_roles;
DROP FUNCTION IF EXISTS tenant.keep_owner_on_account_change();
DROP FUNCTION IF EXISTS tenant.keep_owner_on_role_removal();
DROP FUNCTION IF EXISTS tenant.refuse_last_owner(UUID, UUID);
