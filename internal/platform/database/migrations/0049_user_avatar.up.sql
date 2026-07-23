-- 0049_user_avatar — avatar stored inline as a small data-URL (no object storage yet; image capped/compressed client-side).
-- Only the single-user GET selects it, so the paginated users list stays lean.
ALTER TABLE "user".users ADD COLUMN avatar_url TEXT;
