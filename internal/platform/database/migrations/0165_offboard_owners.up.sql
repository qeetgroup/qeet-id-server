-- 0165_offboard_owners — an organisation can always offboard its own accounts.
--
-- Suspending or deleting an account checked every organisation it owns and
-- refused while any of them would lose its last active owner. Anyone may create
-- an organisation, so an employee who made one could no longer be suspended or
-- deleted by the employer whose account it is, nor deprovisioned by its
-- identity provider. Now only the account's own organisation is kept from
-- losing its last active owner this way; another organisation it owns is left
-- without one. Taking the owner role away is still refused everywhere for the
-- last active owner (0151's keep_owner_on_role_removal, unchanged).
CREATE OR REPLACE FUNCTION tenant.keep_owner_on_account_change() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.tenant_id IS NOT NULL AND EXISTS (
        SELECT 1
        FROM rbac.user_roles ur
        JOIN rbac.roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id AND r.is_system AND r.name = 'owner'
        WHERE ur.user_id = OLD.id AND ur.tenant_id = OLD.tenant_id
    ) THEN
        PERFORM tenant.refuse_last_owner(OLD.tenant_id, OLD.id);
    END IF;
    RETURN NULL;
END;
$$;
