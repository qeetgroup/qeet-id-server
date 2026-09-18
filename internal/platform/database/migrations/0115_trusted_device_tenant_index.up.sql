-- 0115_trusted_device_tenant_index — index trusted devices by tenant.
--
-- auth.trusted_devices (migration 0054) indexes only user_id, because until now
-- every read was "is THIS user's cookie trusted?". The Authentication overview
-- adds a tenant-wide count, which without this index is a sequential scan over
-- every trusted device on the deployment.
--
-- expires_at is in the index because the count only ever asks for live rows —
-- an expired device is no longer trusted and must not inflate the figure.
CREATE INDEX IF NOT EXISTS idx_trusted_devices_tenant
    ON auth.trusted_devices (tenant_id, expires_at);
