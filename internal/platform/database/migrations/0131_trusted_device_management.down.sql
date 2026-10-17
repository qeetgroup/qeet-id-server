DROP TRIGGER IF EXISTS forget_trusted_devices_on_password_change ON auth.password_credentials;
DROP FUNCTION IF EXISTS auth.forget_trusted_devices_on_password_change();
ALTER TABLE tenant.auth_policy DROP COLUMN IF EXISTS remember_device_days;
