-- 0132_push_device_credentials — a linked phone's credential ages out, and
-- the phone can remove itself.
--
-- auth.mfa_push_devices.device_token_expires_at: the device credential the
-- mobile app holds stops working this long after the phone was last linked
-- (180 days; linking again renews it). An expired device receives no approval
-- requests and cannot answer one. Devices already linked get 180 days from now.
ALTER TABLE auth.mfa_push_devices
    ADD COLUMN IF NOT EXISTS device_token_expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '180 days';
