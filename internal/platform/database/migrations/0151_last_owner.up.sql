-- 0151_last_owner — an organisation always keeps an active owner.
--
-- Creating an organisation makes its creator an owner (the organisation's
-- system role 'owner', which holds every permission), and nothing counted the
-- owners afterwards: the only owner could be suspended, soft-deleted or
-- stripped of the role, even by themselves, leaving an organisation nobody can
-- administer, recoverable only in the database.
--
-- These triggers refuse, with SQLSTATE QI409 (the API's 409
-- tenant.last_owner), any change that takes away an organisation's last
-- active owner — an active, non-deleted account holding its owner role. A
-- suspended or deleted owner doesn't count. Every path that suspends,
-- deletes or removes the role is covered, present and future. Concurrent
-- removals queue on a per-organisation lock, so two can't each see the other
-- still there. A deleted organisation keeps no owner: deleting it first frees
-- its owners. To hand ownership over, make someone else an owner first, then
-- remove the old one.

CREATE FUNCTION tenant.refuse_last_owner(p_tenant UUID, p_user UUID) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    -- A deleted organisation (or one whose rows are going with it) has
    -- nothing to keep.
    IF NOT EXISTS (SELECT 1 FROM tenant.tenants WHERE id = p_tenant AND deleted_at IS NULL) THEN
        RETURN;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tenant.last_owner:' || p_tenant::text, 0));
    IF NOT EXISTS (
        SELECT 1
        FROM rbac.user_roles ur
        JOIN rbac.roles r ON r.id = ur.role_id AND r.tenant_id = p_tenant AND r.is_system AND r.name = 'owner'
        JOIN "user".users u ON u.id = ur.user_id
        WHERE ur.tenant_id = p_tenant AND ur.user_id <> p_user
          AND u.status = 'active' AND u.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'organisation % would have no active owner', p_tenant
            USING ERRCODE = 'QI409', HINT = 'Make someone else an owner first.';
    END IF;
END;
$$;

-- An active owner losing the owner role.
CREATE FUNCTION tenant.keep_owner_on_role_removal() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM rbac.roles r
               WHERE r.id = OLD.role_id AND r.tenant_id = OLD.tenant_id AND r.is_system AND r.name = 'owner')
       AND EXISTS (SELECT 1 FROM "user".users u
                   WHERE u.id = OLD.user_id AND u.status = 'active' AND u.deleted_at IS NULL) THEN
        PERFORM tenant.refuse_last_owner(OLD.tenant_id, OLD.user_id);
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER keep_owner_on_role_removal AFTER DELETE ON rbac.user_roles
FOR EACH ROW EXECUTE FUNCTION tenant.keep_owner_on_role_removal();

-- An active owner's account being suspended, deleted or removed: every
-- organisation it owns, in one order, so two such changes can't deadlock.
CREATE FUNCTION tenant.keep_owner_on_account_change() RETURNS TRIGGER LANGUAGE plpgsql AS $$
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

CREATE TRIGGER keep_owner_on_account_change AFTER UPDATE OF status, deleted_at ON "user".users
FOR EACH ROW
WHEN (OLD.status = 'active' AND OLD.deleted_at IS NULL AND (NEW.status <> 'active' OR NEW.deleted_at IS NOT NULL))
EXECUTE FUNCTION tenant.keep_owner_on_account_change();

CREATE TRIGGER keep_owner_on_account_delete AFTER DELETE ON "user".users
FOR EACH ROW
WHEN (OLD.status = 'active' AND OLD.deleted_at IS NULL)
EXECUTE FUNCTION tenant.keep_owner_on_account_change();
