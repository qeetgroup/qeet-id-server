-- 0131_trusted_device_management — remembered devices can be seen and
-- forgotten, last as long as their organisation says, and do not outlive a
-- changed password.
--
-- tenant.auth_policy.remember_device_days: how long a device stays
-- remembered after the sign-in that remembered it, 1–90 days (30 by default).
-- Applies to devices remembered after it is set.
--
-- A changed password forgets every device remembered for the person, so each
-- is asked for the second factor again at its next sign-in.
ALTER TABLE tenant.auth_policy
    ADD COLUMN IF NOT EXISTS remember_device_days INT NOT NULL DEFAULT 30
        CHECK (remember_device_days BETWEEN 1 AND 90);

CREATE FUNCTION auth.forget_trusted_devices_on_password_change() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM auth.trusted_devices WHERE user_id = NEW.user_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER forget_trusted_devices_on_password_change AFTER UPDATE OF password_hash ON auth.password_credentials
FOR EACH ROW WHEN (OLD.password_hash IS DISTINCT FROM NEW.password_hash)
EXECUTE FUNCTION auth.forget_trusted_devices_on_password_change();
