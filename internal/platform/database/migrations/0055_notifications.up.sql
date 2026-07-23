-- 0055_notifications — per-user in-app notification inbox (admin header bell); kind drives icon/color, href is an optional deep link
CREATE TABLE auth.notifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    tenant_id   UUID,
    kind        TEXT NOT NULL DEFAULT 'info',
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    href        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    read_at     TIMESTAMPTZ
);

CREATE INDEX idx_notifications_user_created
    ON auth.notifications (user_id, created_at DESC);
