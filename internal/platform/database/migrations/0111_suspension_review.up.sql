ALTER TABLE "user".users
    ADD COLUMN suspended_at TIMESTAMPTZ,
    ADD COLUMN suspension_reason TEXT CHECK (suspension_reason IN ('unspecified','provider','suspicious_activity','policy_violation','account_compromise','offboarding','inactive','other')),
    ADD COLUMN suspension_source TEXT CHECK (suspension_source IN ('unknown','manual','scim','ldap','policy')),
    ADD COLUMN suspension_risk TEXT CHECK (suspension_risk IN ('unknown','low','medium','high')),
    ADD COLUMN suspension_review TEXT CHECK (suspension_review IN ('pending','reviewed'));

CREATE FUNCTION "user".capture_suspension_transition() RETURNS TRIGGER LANGUAGE plpgsql AS $$
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

CREATE TRIGGER capture_suspension_transition BEFORE INSERT OR UPDATE OF status ON "user".users
FOR EACH ROW EXECUTE FUNCTION "user".capture_suspension_transition();

CREATE INDEX users_suspended_tenant ON "user".users(tenant_id,suspended_at DESC,id) WHERE status='suspended' AND deleted_at IS NULL;
