-- Push MFA: device registry + challenge log.
-- Devices are scoped to users only (no tenant_id), matching the rest of the mfa
-- schema. Challenges carry a context blob (ip, location, device, timestamp) that
-- the mobile app displays before the user approves or denies.

CREATE TABLE auth.mfa_push_devices (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    name         text        NOT NULL DEFAULT '',
    push_token   text        NOT NULL,
    platform     text        NOT NULL CHECK (platform IN ('ios', 'android')),
    -- device_token is issued once at registration and stored by the app;
    -- it authenticates challenge-response calls from that specific device.
    device_token text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT NOW(),
    last_seen_at timestamptz NOT NULL DEFAULT NOW()
);

-- A user re-registering the same push token rotates the device_token.
CREATE UNIQUE INDEX mfa_push_devices_user_token ON auth.mfa_push_devices (user_id, push_token);

CREATE TABLE auth.mfa_push_challenges (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    action       text        NOT NULL,
    context      jsonb       NOT NULL DEFAULT '{}',
    status       text        NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    expires_at   timestamptz NOT NULL DEFAULT NOW() + interval '2 minutes',
    created_at   timestamptz NOT NULL DEFAULT NOW(),
    responded_at timestamptz
);

CREATE INDEX mfa_push_challenges_user_status ON auth.mfa_push_challenges (user_id, status, expires_at);
