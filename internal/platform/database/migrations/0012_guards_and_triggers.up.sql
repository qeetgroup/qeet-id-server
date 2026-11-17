-- 0012_guards_and_triggers — the rules the database itself keeps.
--
-- The owner guards refuse, with SQLSTATE QI409, any change that would leave an
-- organization without an active owner. They are SECURITY DEFINER so they see
-- every organization's rows whatever the connection is scoped to. The other
-- triggers end what a password change or a suspension must end.

CREATE FUNCTION organization.keep_owner_on_account_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.organization_id IS NOT NULL AND EXISTS (
        SELECT 1
        FROM rbac.user_roles ur
        JOIN rbac.roles r ON r.id = ur.role_id AND r.organization_id = ur.organization_id AND r.is_system AND r.name = 'owner'
        WHERE ur.user_id = OLD.id AND ur.organization_id = OLD.organization_id
    ) THEN
        PERFORM organization.refuse_last_owner(OLD.organization_id, OLD.id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION organization.keep_owner_on_role_removal() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM rbac.roles r
               WHERE r.id = OLD.role_id AND r.organization_id = OLD.organization_id AND r.is_system AND r.name = 'owner')
       AND EXISTS (SELECT 1 FROM account.users u
                   WHERE u.id = OLD.user_id AND u.status = 'active' AND u.deleted_at IS NULL) THEN
        PERFORM organization.refuse_last_owner(OLD.organization_id, OLD.user_id);
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION organization.refuse_last_owner(p_organization uuid, p_user uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    -- A deleted organization (or one whose rows are going with it) has
    -- nothing to keep.
    IF NOT EXISTS (SELECT 1 FROM organization.organizations WHERE id = p_organization AND deleted_at IS NULL) THEN
        RETURN;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tenant.last_owner:' || p_organization::text, 0));
    IF NOT EXISTS (
        SELECT 1
        FROM rbac.user_roles ur
        JOIN rbac.roles r ON r.id = ur.role_id AND r.organization_id = p_organization AND r.is_system AND r.name = 'owner'
        JOIN account.users u ON u.id = ur.user_id
        WHERE ur.organization_id = p_organization AND ur.user_id <> p_user
          AND u.status = 'active' AND u.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'organisation % would have no active owner', p_organization
            USING ERRCODE = 'QI409', HINT = 'Make someone else an owner first.';
    END IF;
END;
$$;

CREATE FUNCTION auth.clear_step_ups_on_password_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM auth.mfa_verifications WHERE user_id = NEW.user_id;
    RETURN NEW;
END;
$$;

CREATE FUNCTION auth.forget_trusted_devices_on_password_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM auth.trusted_devices WHERE user_id = NEW.user_id;
    RETURN NEW;
END;
$$;

CREATE FUNCTION account.capture_suspension_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.status = 'suspended' AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM 'suspended') THEN
        NEW.suspended_at := NOW();
        NEW.suspension_reason := 'unspecified';
        NEW.suspension_source := 'unknown';
        NEW.suspension_risk := 'unknown';
        NEW.suspension_review := 'pending';
    ELSIF NEW.status <> 'suspended' THEN
        NEW.suspended_at := NULL;
        NEW.suspension_reason := NULL;
        NEW.suspension_source := NULL;
        NEW.suspension_risk := NULL;
        NEW.suspension_review := NULL;
    END IF;
    RETURN NEW;
END;
$$;



SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TRIGGER clear_step_ups_on_password_change AFTER UPDATE OF password_hash ON auth.password_credentials FOR EACH ROW WHEN ((old.password_hash IS DISTINCT FROM new.password_hash)) EXECUTE FUNCTION auth.clear_step_ups_on_password_change();
CREATE TRIGGER forget_trusted_devices_on_password_change AFTER UPDATE OF password_hash ON auth.password_credentials FOR EACH ROW WHEN ((old.password_hash IS DISTINCT FROM new.password_hash)) EXECUTE FUNCTION auth.forget_trusted_devices_on_password_change();
CREATE TRIGGER keep_owner_on_role_removal AFTER DELETE ON rbac.user_roles FOR EACH ROW EXECUTE FUNCTION organization.keep_owner_on_role_removal();
CREATE TRIGGER capture_suspension_transition BEFORE INSERT OR UPDATE OF status ON account.users FOR EACH ROW EXECUTE FUNCTION account.capture_suspension_transition();
CREATE TRIGGER keep_owner_on_account_change AFTER UPDATE OF status, deleted_at ON account.users FOR EACH ROW WHEN (((old.status = 'active'::text) AND (old.deleted_at IS NULL) AND ((new.status <> 'active'::text) OR (new.deleted_at IS NOT NULL)))) EXECUTE FUNCTION organization.keep_owner_on_account_change();
CREATE TRIGGER keep_owner_on_account_delete AFTER DELETE ON account.users FOR EACH ROW WHEN (((old.status = 'active'::text) AND (old.deleted_at IS NULL))) EXECUTE FUNCTION organization.keep_owner_on_account_change();
