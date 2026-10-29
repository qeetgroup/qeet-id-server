CREATE OR REPLACE FUNCTION tenant.keep_owner_on_account_change() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    owned UUID;
BEGIN
    FOR owned IN
        SELECT ur.tenant_id
        FROM rbac.user_roles ur
        JOIN rbac.roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id AND r.is_system AND r.name = 'owner'
        WHERE ur.user_id = OLD.id
        ORDER BY ur.tenant_id
    LOOP
        PERFORM tenant.refuse_last_owner(owned, OLD.id);
    END LOOP;
    RETURN NULL;
END;
$$;
